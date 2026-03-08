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
from pow_captcha_server.interfaces import CaptchaResponse, CaptchaRequestState, CaptchaValidatedPOW
import collections
import threading
import os
from .storage import MemoryStorage, RedisStorage

class POWCaptchaServer:
    class POWCaptchaError(Exception):
        def __init__(self, message: str):
            self.message = message
            super().__init__(self.message)
    class ChallengeNotFoundOrExpired(POWCaptchaError):
        def __init__(self):
            super().__init__("Challenge not found or expired")
    class DifficultyMismatch(POWCaptchaError):
        def __init__(self):
            super().__init__("Difficulty mismatch")
    class InvalidProofOfWork(POWCaptchaError):
        def __init__(self):
            super().__init__("Invalid Proof of Work")
    class ChallengeAlreadyActive(POWCaptchaError):
        def __init__(self):
            super().__init__("Challenge already active")

    MAX_ACTIVE_CHALLENGES = 10000

    def __init__(self, default_difficulty: int, validity_seconds: int = 300, enable_fingerprint: bool = False, request_minimum_delay: float | None = None, cookie_ttl: int = 3600):
        self.default_difficulty = default_difficulty
        self.validity_seconds = validity_seconds
        self.enable_fingerprint = enable_fingerprint
        self.request_minimum_delay = request_minimum_delay
        self.cookie_ttl = cookie_ttl
        self._server_secret = secrets.token_bytes(64)

        self.lock = threading.Lock()

        redis_url = os.environ.get("POW_REDIS_URL")
        if redis_url:
            self.storage = RedisStorage(redis_url, max_challenges=self.MAX_ACTIVE_CHALLENGES)
        else:
            self.storage = MemoryStorage(max_challenges=self.MAX_ACTIVE_CHALLENGES)

    def _generate_client_hash(self, ip: IPv4Address | IPv6Address, user_agent: str, fingerprint: str) -> str:
        data = f"{str(ip)}|{user_agent}|{fingerprint}".encode('utf-8')
        return hashlib.sha256(data).hexdigest()

    def generate_clearance_token(self, ip: IPv4Address | IPv6Address, user_agent: str, fingerprint: str) -> str:
        exp = int(time.time()) + self.cookie_ttl
        client_hash = self._generate_client_hash(ip, user_agent, fingerprint)
        payload = f"{exp}:{client_hash}"
        signature = hmac.new(self._server_secret, payload.encode('utf-8'), hashlib.sha256).hexdigest()
        return f"{payload}:{signature}"

    def validate_clearance_token(self, token: str, ip: IPv4Address | IPv6Address, user_agent: str, fingerprint: str) -> bool:
        parts = token.split(':')
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
        expected_sig = hmac.new(self._server_secret, payload.encode('utf-8'), hashlib.sha256).hexdigest()

        if not secrets.compare_digest(expected_sig, sig_str):
            return False

        return True

    @staticmethod
    def _b64url_encode(b: bytes) -> str:
        return base64.b64encode(b).decode('ascii')

    @staticmethod
    def _get_subnet_prefix(ip: IPv4Address | IPv6Address) -> str:
        string_ip = str(ip)
        if isinstance(ip, IPv4Address):
            # Return /24 subnet (e.g. 203.0.113.1 -> 203.0.113)
            return ".".join(string_ip.split(".")[:3])
        else:
            # Return /48 subnet for IPv6
            return ":".join(string_ip.split(":")[:3])

    @staticmethod
    def _b64url_decode(s: str) -> bytes:
        return base64.b64decode(s)

    async def get_challenge(self, client_ip: IPv4Address | IPv6Address, fingerprint: str | None = None) -> CaptchaResponse:
        now = datetime.now(timezone.utc)

        if await self.storage.is_ip_active(str(client_ip)):
            raise POWCaptchaServer.ChallengeAlreadyActive()

        if await self.storage.count_challenges() >= self.MAX_ACTIVE_CHALLENGES:
            raise POWCaptchaServer.POWCaptchaError("Server busy, try again later")

        dynamic_difficulty = self.default_difficulty
        subnet_prefix = self._get_subnet_prefix(client_ip)
        
        subnet_count = await self.storage.get_subnet_history(subnet_prefix)
        dynamic_difficulty += subnet_count // 5
        
        if self.enable_fingerprint and fingerprint:
            history_count = await self.storage.get_fingerprint_history(fingerprint)
            dynamic_difficulty += history_count // 5
        
        recent_global_solves = await self.storage.get_recent_global_solves_count(60)
        if recent_global_solves > 50:
            panic_penalty = (recent_global_solves - 50) // 10
            dynamic_difficulty += panic_penalty

        ip_salt = hashlib.sha256(str(client_ip).encode('utf-8') + self._server_secret).digest()
        challenge_bytes = secrets.token_bytes(16) + ip_salt[:16]
        
        req_id = str(uuid7())
        
        try:
            await self.storage.add_challenge(
                req_id,
                challenge_bytes,
                str(client_ip),
                dynamic_difficulty,
                now,
                self.validity_seconds
            )
        except Exception:
            raise POWCaptchaServer.POWCaptchaError("Server busy, try again later")
        
        return CaptchaResponse(
            challenge=self._b64url_encode(challenge_bytes),
            difficulty=dynamic_difficulty,
            req_id=req_id
        )

    def validate_pow_hash(self, h: bytes, difficulty_bits: int) -> bool:
        for i in range(32):
            bits_to_keep = max(0, min(8, difficulty_bits - i * 8))
            if bits_to_keep == 0:
                continue
            mask = (0xFF << (8 - bits_to_keep)) & 0xFF
            if (h[i] & mask) != 0:
                return False
        return True

    async def verify_pow(self, request: CaptchaValidatedPOW, client_ip: IPv4Address | IPv6Address, fingerprint: str | None = None) -> bool:
        query_start = datetime.now(timezone.utc)
        
        state = await self.storage.get_and_delete_challenge(str(request.req_id))

        if not state:
            raise POWCaptchaServer.ChallengeNotFoundOrExpired()
        
        if state['ip'] != str(client_ip):
            raise POWCaptchaServer.ChallengeNotFoundOrExpired()

        now = datetime.now(timezone.utc)
        elapsed_time = (now - state['timestamp']).total_seconds()
        
        if elapsed_time > self.validity_seconds:
            raise POWCaptchaServer.ChallengeNotFoundOrExpired()

        if request.difficulty != state['difficulty']:
            raise POWCaptchaServer.DifficultyMismatch()

        try:
            challenge_bytes = self._b64url_decode(request.challenge)
            nonce_bytes = self._b64url_decode(request.nonce)
        except Exception:
            raise POWCaptchaServer.InvalidProofOfWork()

        if not secrets.compare_digest(challenge_bytes, state['challenge']):
            raise POWCaptchaServer.InvalidProofOfWork()

        # Argon2id: password=nonce, salt=challenge
        # Parameters must match client-js: time=1, mem=19456 KiB, parallelism=1, hashLen=32
        computed_hash = argon2_low_level.hash_secret_raw(
            secret=nonce_bytes,
            salt=challenge_bytes,
            time_cost=1,
            memory_cost=19456,
            parallelism=1,
            hash_len=32,
            type=argon2_low_level.Type.ID
        )

        if not self.validate_pow_hash(computed_hash, state['difficulty']):
            raise POWCaptchaServer.InvalidProofOfWork()

        # Track fingerprint, subnet & global success
        await self.storage.add_global_solve(datetime.now(timezone.utc))
        subnet_prefix = self._get_subnet_prefix(client_ip)
        await self.storage.increment_subnet_history(subnet_prefix)
        if self.enable_fingerprint and fingerprint:
            await self.storage.increment_fingerprint_history(fingerprint)

        if self.request_minimum_delay is not None:
            elapsed_processing = (datetime.now(timezone.utc) - query_start).total_seconds()
            if elapsed_processing < self.request_minimum_delay:
                await asyncio.sleep(self.request_minimum_delay - elapsed_processing)
        return True