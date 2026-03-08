"""
Core Proof-of-Work Captcha logic.

All security-relevant operations use constant-time comparison (via
`hmac.compare_digest` / `secrets.compare_digest`).  Argon2id parameters
are kept in sync with client-js and both other server implementations.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import base64
import time
from argon2 import low_level as argon2_low_level
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address
from uuid_extensions import uuid7
import asyncio
from powchallenge_server.interfaces import (
    CaptchaResponse,
    CaptchaValidatedPOW,
    IPAddress,
)
from powchallenge_server.storage import (
    StorageBackend,
    MemoryStorage,
    RedisStorage,
    ChallengeState,
)
import os


# ──────────────────────────────────────────────────────────────────────────────
# Argon2id parameters — must stay in sync with client-js and all servers
# ──────────────────────────────────────────────────────────────────────────────
_ARGON2_TIME_COST: int = 1
_ARGON2_MEMORY_COST: int = 19456  # KiB — 19 MiB, GPU-hostile
_ARGON2_PARALLELISM: int = 1
_ARGON2_HASH_LEN: int = 32

# Maximum byte length of a decoded nonce (DoS guard — SEC-3).
# Client always uses 32 bytes; we allow up to 64 for future flexibility.
_NONCE_MAX_BYTES: int = 64


# ──────────────────────────────────────────────────────────────────────────────
# Exceptions
# ──────────────────────────────────────────────────────────────────────────────

class POWCaptchaError(Exception):
    """Base class for all domain errors raised by POWCaptchaServer."""
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class ChallengeNotFoundOrExpired(POWCaptchaError):
    def __init__(self) -> None:
        super().__init__("Challenge not found or expired")


class DifficultyMismatch(POWCaptchaError):
    def __init__(self) -> None:
        super().__init__("Difficulty mismatch")


class InvalidProofOfWork(POWCaptchaError):
    def __init__(self) -> None:
        super().__init__("Invalid Proof of Work")


class ChallengeAlreadyActive(POWCaptchaError):
    def __init__(self) -> None:
        super().__init__("Challenge already active")


class ServerBusy(POWCaptchaError):
    def __init__(self) -> None:
        super().__init__("Server busy, try again later")


# ──────────────────────────────────────────────────────────────────────────────
# Server
# ──────────────────────────────────────────────────────────────────────────────

class POWCaptchaServer:
    def __init__(
        self,
        default_difficulty: int,
        validity_seconds: int = 300,
        enable_fingerprint: bool = False,
        request_minimum_delay: float | None = None,
        cookie_ttl: int = 3600,
    ) -> None:
        self._default_difficulty: int = default_difficulty
        self._validity_seconds: int = validity_seconds
        self._enable_fingerprint: bool = enable_fingerprint
        self._request_minimum_delay: float | None = request_minimum_delay
        self._cookie_ttl: int = cookie_ttl
        self._server_secret: bytes = secrets.token_bytes(64)
        self._max_active_challenges: int = 10000

        redis_url: str | None = os.environ.get("POW_REDIS_URL")
        self._storage: StorageBackend
        if redis_url:
            self._storage = RedisStorage(redis_url, max_challenges=self._max_active_challenges)
        else:
            self._storage = MemoryStorage(max_challenges=self._max_active_challenges)

    # ── Public property so callers never need to touch internals ──────────────

    def set_max_active_challenges(self, max_challenges: int) -> None:
        """Update the global cap on simultaneous in-flight challenges."""
        self._max_active_challenges = max_challenges
        # Propagate to the concrete storage instance (works for both backends)
        self._storage.max_challenges = max_challenges  # type: ignore[union-attr]

    # ── Clearance token (optional post-solve cookie) ───────────────────────

    def _generate_client_hash(self, ip: IPAddress, user_agent: str, fingerprint: str) -> str:
        data = f"{ip}|{user_agent}|{fingerprint}".encode("utf-8")
        return hashlib.sha256(data).hexdigest()

    def generate_clearance_token(self, ip: IPAddress, user_agent: str, fingerprint: str) -> str:
        exp = int(time.time()) + self._cookie_ttl
        client_hash = self._generate_client_hash(ip, user_agent, fingerprint)
        payload = f"{exp}:{client_hash}"
        signature = hmac.new(self._server_secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{payload}:{signature}"

    def validate_clearance_token(
        self, token: str, ip: IPAddress, user_agent: str, fingerprint: str
    ) -> bool:
        parts = token.split(":")
        if len(parts) != 3:
            return False

        exp_str, hash_str, sig_str = parts

        try:
            exp = int(exp_str)
        except ValueError:
            return False

        if int(time.time()) > exp:
            return False

        expected_hash = self._generate_client_hash(ip, user_agent, fingerprint)
        if not secrets.compare_digest(expected_hash, hash_str):
            return False

        payload = f"{exp_str}:{hash_str}"
        expected_sig = hmac.new(self._server_secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return secrets.compare_digest(expected_sig, sig_str)

    # ── Internal helpers ───────────────────────────────────────────────────

    @staticmethod
    def _b64_encode(b: bytes) -> str:
        return base64.b64encode(b).decode("ascii")

    @staticmethod
    def _b64_decode(s: str) -> bytes:
        return base64.b64decode(s)

    @staticmethod
    def _get_subnet_prefix(ip: IPAddress) -> str:
        s = str(ip)
        if isinstance(ip, IPv4Address):
            return ".".join(s.split(".")[:3])
        # IPv6: /48 prefix (first 3 groups)
        return ":".join(s.split(":")[:3])

    @staticmethod
    def _validate_pow_hash(h: bytes, difficulty_bits: int) -> bool:
        """Return True if the first `difficulty_bits` bits of `h` are all zero."""
        for i in range(_ARGON2_HASH_LEN):
            bits_to_check = max(0, min(8, difficulty_bits - i * 8))
            if bits_to_check == 0:
                break
            mask = (0xFF << (8 - bits_to_check)) & 0xFF
            if (h[i] & mask) != 0:
                return False
        return True

    # ── Core API ───────────────────────────────────────────────────────────

    async def get_challenge(
        self,
        client_ip: IPAddress,
        fingerprint: str | None = None,
    ) -> CaptchaResponse:
        now = datetime.now(timezone.utc)
        ip_str = str(client_ip)

        if await self._storage.is_ip_active(ip_str):
            raise ChallengeAlreadyActive()

        if await self._storage.count_challenges() >= self._max_active_challenges:
            raise ServerBusy()

        dynamic_difficulty = self._default_difficulty
        subnet_prefix = self._get_subnet_prefix(client_ip)

        subnet_count = await self._storage.get_subnet_history(subnet_prefix)
        dynamic_difficulty += subnet_count // 5

        if self._enable_fingerprint and fingerprint:
            fp_count = await self._storage.get_fingerprint_history(fingerprint)
            dynamic_difficulty += fp_count // 5

        recent_global = await self._storage.get_recent_global_solves_count(60)
        if recent_global > 50:
            dynamic_difficulty += (recent_global - 50) // 10

        ip_salt = hashlib.sha256(ip_str.encode("utf-8") + self._server_secret).digest()
        challenge_bytes = secrets.token_bytes(16) + ip_salt[:16]
        req_id = str(uuid7())

        try:
            await self._storage.store_challenge(
                req_id,
                challenge_bytes,
                ip_str,
                dynamic_difficulty,
                now,
                self._validity_seconds,
            )
        except Exception:
            raise ServerBusy()

        return CaptchaResponse(
            challenge=self._b64_encode(challenge_bytes),
            difficulty=dynamic_difficulty,
            req_id=req_id,  # type: ignore[arg-type]  # pydantic coerces str → UUID7
        )

    async def verify_pow(
        self,
        request: CaptchaValidatedPOW,
        client_ip: IPAddress,
        fingerprint: str | None = None,
    ) -> bool:
        query_start = datetime.now(timezone.utc)
        ip_str = str(client_ip)

        state: ChallengeState | None = await self._storage.fetch_challenge(
            str(request.req_id)
        )

        if state is None:
            raise ChallengeNotFoundOrExpired()

        deleted = await self._storage.delete_challenge(str(request.req_id))
        if not deleted:
            raise ChallengeNotFoundOrExpired()

        if state["ip"] != ip_str:
            raise ChallengeNotFoundOrExpired()

        now = datetime.now(timezone.utc)
        if (now - state["timestamp"]).total_seconds() > self._validity_seconds:
            raise ChallengeNotFoundOrExpired()

        if request.difficulty != state["difficulty"]:
            raise DifficultyMismatch()

        try:
            challenge_bytes = self._b64_decode(request.challenge)
            nonce_bytes = self._b64_decode(request.nonce)
        except Exception:
            raise InvalidProofOfWork()

        # SEC-3: guard against oversized nonce DoS
        if len(nonce_bytes) > _NONCE_MAX_BYTES:
            raise InvalidProofOfWork()

        if not secrets.compare_digest(challenge_bytes, state["challenge"]):
            raise InvalidProofOfWork()

        # Argon2id — parameters must exactly match client-js
        computed_hash: bytes = argon2_low_level.hash_secret_raw(
            secret=nonce_bytes,
            salt=challenge_bytes,
            time_cost=_ARGON2_TIME_COST,
            memory_cost=_ARGON2_MEMORY_COST,
            parallelism=_ARGON2_PARALLELISM,
            hash_len=_ARGON2_HASH_LEN,
            type=argon2_low_level.Type.ID,
        )

        if not self._validate_pow_hash(computed_hash, state["difficulty"]):
            raise InvalidProofOfWork()

        await self._storage.add_global_solve(datetime.now(timezone.utc))
        subnet_prefix = self._get_subnet_prefix(client_ip)
        await self._storage.increment_subnet_history(subnet_prefix)
        if self._enable_fingerprint and fingerprint:
            await self._storage.increment_fingerprint_history(fingerprint)

        if self._request_minimum_delay is not None:
            elapsed = (datetime.now(timezone.utc) - query_start).total_seconds()
            if elapsed < self._request_minimum_delay:
                await asyncio.sleep(self._request_minimum_delay - elapsed)

        return True