from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from powchallenge_server.core import (
    POWCaptchaError,
    ChallengeAlreadyActive,
    ServerBusy,
    POWCaptchaServer,
)
from powchallenge_server.interfaces import CaptchaResponse, CaptchaValidatedPOW

app = FastAPI(title="POW Captcha Server")

# ── Validation error → 400 / Invalid JSON ────────────────────────────────────

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    return JSONResponse(status_code=400, content={"error": "Invalid JSON"})


# ── Client-JS bundling (runs once at startup) ─────────────────────────────────

def _setup_client_js() -> None:
    fastapi_dir = Path(__file__).resolve().parent
    base_dir = fastapi_dir.parents[3]
    client_js_dir = base_dir / "client-js"
    js_target_dir = fastapi_dir / "js"
    js_target_dir.mkdir(exist_ok=True)
    dst_file = js_target_dir / "bundle.min.js"
    if dst_file.exists():
        return  # already built — skip webpack to avoid blocking server startup
    print("Compiling client-js…")
    try:
        subprocess.run(["npm", "run", "build"], cwd=client_js_dir, check=True, shell=(os.name == "nt"))
        src_file = client_js_dir / "dist" / "bundle.min.js"
        if src_file.exists():
            shutil.copy2(src_file, dst_file)
            print(f"Copied {src_file} → {dst_file}")
        else:
            print(f"Warning: {src_file} not found after build.")
    except Exception as exc:
        print(f"Warning: could not build client-js: {exc}")


_setup_client_js()

app.mount(
    "/js",
    StaticFiles(directory=str(Path(__file__).resolve().parent / "js")),
    name="js",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── POW server instance ───────────────────────────────────────────────────────

_difficulty = int(os.environ.get("POW_DEFAULT_DIFFICULTY", "10"))
_pow_server = POWCaptchaServer(default_difficulty=_difficulty, validity_seconds=300)


# ── Request helpers ───────────────────────────────────────────────────────────

def _get_ip(request: Request) -> IPv4Address | IPv6Address:
    """Extract and normalise the real client IP (handles X-Forwarded-For)."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        raw = forwarded.split(",")[-1].strip()
    else:
        raw = request.headers.get("x-real-ip") or (
            request.client.host if request.client and request.client.host else "127.0.0.1"
        )
    parsed = ip_address(raw)
    # Normalise IPv4-mapped IPv6 (::ffff:1.2.3.4 → 1.2.3.4) to prevent
    # subnet-bucket collapse (SEC-5).
    if isinstance(parsed, IPv6Address) and parsed.ipv4_mapped:
        return parsed.ipv4_mapped
    return parsed


def _get_fingerprint(request: Request) -> str:
    """Build a server-side fingerprint from HTTP request metadata."""
    components = [
        str(_get_ip(request)),
        request.headers.get("user-agent", ""),
        request.headers.get("accept-language", ""),
        request.headers.get("accept-encoding", ""),
        request.headers.get("sec-ch-ua", ""),
        request.headers.get("sec-ch-ua-platform", ""),
        request.headers.get("sec-fetch-dest", ""),
        request.headers.get("sec-fetch-mode", ""),
        request.headers.get("sec-fetch-site", ""),
        ",".join(k.lower() for k in request.headers.keys()),
    ]
    return hashlib.sha256("|".join(components).encode("utf-8")).hexdigest()


# ── Status-code mapping for business errors ───────────────────────────────────

_ERROR_STATUS: dict[type[POWCaptchaError], int] = {
    ChallengeAlreadyActive: 429,
    ServerBusy: 503,
}


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=FileResponse)
async def serve_index() -> FileResponse:
    return FileResponse(Path(__file__).resolve().parent / "index.html")


@app.get("/challenge")
async def get_challenge(request: Request) -> JSONResponse:
    try:
        result = await _pow_server.get_challenge(_get_ip(request), _get_fingerprint(request))
        return JSONResponse(content=result.model_dump(mode="json"))
    except Exception as exc:
        name = type(exc).__name__
        if name in ("ChallengeAlreadyActive", "ServerBusy", "POWCaptchaError", "DifficultyMismatch", "InvalidProofOfWork", "ChallengeNotFoundOrExpired"):
            status = 429 if name == "ChallengeAlreadyActive" else 503 if name == "ServerBusy" else 400
            msg = getattr(exc, "message", str(exc))
            return JSONResponse(status_code=status, content={"error": msg})
        return JSONResponse(status_code=500, content={"error": str(exc)})


@app.post("/verify")
async def verify_challenge(payload: CaptchaValidatedPOW, request: Request) -> JSONResponse:
    try:
        await _pow_server.verify_pow(payload, _get_ip(request), _get_fingerprint(request))
        return JSONResponse(content={"message": "Proof of Work validated successfully."})
    except Exception as exc:
        name = type(exc).__name__
        if name in ("ChallengeAlreadyActive", "ServerBusy", "POWCaptchaError", "DifficultyMismatch", "InvalidProofOfWork", "ChallengeNotFoundOrExpired"):
            status = 429 if name == "ChallengeAlreadyActive" else 503 if name == "ServerBusy" else 400
            msg = getattr(exc, "message", str(exc))
            return JSONResponse(status_code=status, content={"error": msg})
        return JSONResponse(status_code=500, content={"error": str(exc)})


if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 8080))
    # Note: using "server:app" works if cwd is where server.py lives
    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=False)
