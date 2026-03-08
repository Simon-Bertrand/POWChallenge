from fastapi import FastAPI, Request, HTTPException, status, Body
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
import os
import sys
from ipaddress import IPv4Address, IPv6Address

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from powchallenge_server.core import POWCaptchaServer
from powchallenge_server.interfaces import CaptchaValidatedPOW

app = FastAPI()

captcha = POWCaptchaServer(default_difficulty=int(os.environ.get("POW_DEFAULT_DIFFICULTY", "10")), validity_seconds=300)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=400,
        content={"error": "Invalid JSON"},
    )

def get_client_ip(request: Request) -> IPv4Address | IPv6Address:
    forwarded = request.headers.get("x-forwarded-for")
    ip_str = forwarded.split(',')[0].strip() if forwarded else request.client.host
    try:
        return IPv4Address(ip_str)
    except:
        try:
            return IPv6Address(ip_str)
        except:
            return IPv4Address("127.0.0.1")

@app.get("/challenge")
async def get_challenge(request: Request):
    ip = get_client_ip(request)
    try:
        resp = await captcha.get_challenge(ip)
        return resp
    except Exception as e:
        if type(e).__name__ == "ChallengeAlreadyActive":
            return JSONResponse(status_code=429, content={"error": "Challenge already active"})
        elif hasattr(e, "message"):
            return JSONResponse(status_code=400, content={"error": e.message})
        return JSONResponse(status_code=500, content={"error": str(e)})

from powchallenge_server.core import ChallengeNotFoundOrExpired, InvalidProofOfWork, DifficultyMismatch, ChallengeAlreadyActive

@app.post("/verify")
async def verify(request: Request, payload: dict = Body(...)):
    ip = get_client_ip(request)
    try:
        val_pow = CaptchaValidatedPOW(**payload)
        await captcha.verify_pow(val_pow, ip)
        return {"message": "Proof of Work validated successfully."}
    except Exception as e:
        if type(e).__name__ in ["InvalidProofOfWork", "DifficultyMismatch", "ChallengeNotFoundOrExpired"]:
            return JSONResponse(status_code=400, content={"error": str(e)})
        return JSONResponse(status_code=400, content={"error": str(e)})

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8081))
    uvicorn.run("server:app", host="0.0.0.0", port=port, log_level="info")
