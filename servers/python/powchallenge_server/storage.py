"""
Storage backends for POW Captcha Server.

Both backends implement the `StorageBackend` Protocol so that the core
library never needs to import a concrete class — only the protocol is used
for type-checking.
"""

from __future__ import annotations

import collections
import json
from datetime import datetime, timezone
from typing import Optional, TypedDict, Protocol, runtime_checkable


# ──────────────────────────────────────────────────────────────────────────────
# Shared TypedDict for in-flight challenge state
# ──────────────────────────────────────────────────────────────────────────────

class ChallengeState(TypedDict):
    challenge: bytes
    ip: str
    timestamp: datetime
    difficulty: int


# ──────────────────────────────────────────────────────────────────────────────
# Storage Protocol (replaces BaseStorage inheritance)
# ──────────────────────────────────────────────────────────────────────────────

@runtime_checkable
class StorageBackend(Protocol):
    async def add_challenge(
        self,
        req_id: str,
        challenge_bytes: bytes,
        ip: str,
        difficulty: int,
        timestamp: datetime,
        validity_seconds: int,
    ) -> None: ...

    async def get_and_delete_challenge(self, req_id: str) -> Optional[ChallengeState]: ...
    async def count_challenges(self) -> int: ...
    async def is_ip_active(self, ip: str) -> bool: ...
    async def increment_subnet_history(self, subnet: str) -> None: ...
    async def get_subnet_history(self, subnet: str) -> int: ...
    async def increment_fingerprint_history(self, fingerprint: str) -> None: ...
    async def get_fingerprint_history(self, fingerprint: str) -> int: ...
    async def add_global_solve(self, timestamp: datetime) -> None: ...
    async def get_recent_global_solves_count(self, window_seconds: int) -> int: ...


# ──────────────────────────────────────────────────────────────────────────────
# In-memory implementation
# ──────────────────────────────────────────────────────────────────────────────

class MemoryStorage:
    def __init__(self, max_challenges: int = 10000) -> None:
        self._active_challenges: dict[str, ChallengeState] = {}
        self._active_ips: set[str] = set()
        self._fingerprint_history: collections.Counter[str] = collections.Counter()
        self._subnet_history: collections.Counter[str] = collections.Counter()
        self._global_solve_history: collections.deque[datetime] = collections.deque(maxlen=1000)
        self.max_challenges: int = max_challenges

    def _cleanup_expired(self, validity_seconds: int) -> None:
        now = datetime.now(timezone.utc)
        to_delete = [
            req_id
            for req_id, state in self._active_challenges.items()
            if (now - state["timestamp"]).total_seconds() > validity_seconds
        ]
        for req_id in to_delete:
            state = self._active_challenges.pop(req_id, None)
            if state:
                self._active_ips.discard(state["ip"])

    async def add_challenge(
        self,
        req_id: str,
        challenge_bytes: bytes,
        ip: str,
        difficulty: int,
        timestamp: datetime,
        validity_seconds: int,
    ) -> None:
        self._cleanup_expired(validity_seconds)
        if len(self._active_challenges) >= self.max_challenges:
            raise RuntimeError("Server busy")
        self._active_challenges[req_id] = {
            "challenge": challenge_bytes,
            "ip": ip,
            "timestamp": timestamp,
            "difficulty": difficulty,
        }
        self._active_ips.add(ip)

    async def get_and_delete_challenge(self, req_id: str) -> Optional[ChallengeState]:
        state = self._active_challenges.pop(req_id, None)
        if state:
            self._active_ips.discard(state["ip"])
        return state

    async def count_challenges(self) -> int:
        return len(self._active_challenges)

    async def is_ip_active(self, ip: str) -> bool:
        return ip in self._active_ips

    async def increment_subnet_history(self, subnet: str) -> None:
        self._subnet_history[subnet] += 1
        if len(self._subnet_history) > 10000:
            top = self._subnet_history.most_common(5000)
            self._subnet_history.clear()
            self._subnet_history.update(dict(top))

    async def get_subnet_history(self, subnet: str) -> int:
        return self._subnet_history.get(subnet, 0)

    async def increment_fingerprint_history(self, fingerprint: str) -> None:
        self._fingerprint_history[fingerprint] += 1
        if len(self._fingerprint_history) > 10000:
            top = self._fingerprint_history.most_common(5000)
            self._fingerprint_history.clear()
            self._fingerprint_history.update(dict(top))

    async def get_fingerprint_history(self, fingerprint: str) -> int:
        return self._fingerprint_history.get(fingerprint, 0)

    async def add_global_solve(self, timestamp: datetime) -> None:
        self._global_solve_history.append(timestamp)

    async def get_recent_global_solves_count(self, window_seconds: int) -> int:
        now = datetime.now(timezone.utc)
        while self._global_solve_history and (
            (now - self._global_solve_history[0]).total_seconds() > window_seconds
        ):
            self._global_solve_history.popleft()
        return len(self._global_solve_history)


# ──────────────────────────────────────────────────────────────────────────────
# Redis implementation (optional; only available when redis-py is installed)
# ──────────────────────────────────────────────────────────────────────────────

# Lua script: atomically GET then DEL a key. Returns the value or false.
# This prevents the TOCTOU race where two concurrent requests both GET
# the same challenge before either DEL runs.
_LUA_GET_AND_DELETE = """
local v = redis.call('GET', KEYS[1])
if v then
    redis.call('DEL', KEYS[1])
    return v
end
return false
"""

try:
    import redis.asyncio as _redis

    class RedisStorage:
        def __init__(self, redis_url: str, max_challenges: int = 10000) -> None:
            self._r: _redis.Redis = _redis.from_url(redis_url)
            self.max_challenges: int = max_challenges
            self._prefix: str = "pow_captcha:"
            # Register Lua scripts once at init for efficiency
            self._script_get_del = self._r.register_script(_LUA_GET_AND_DELETE)

        async def count_challenges(self) -> int:
            now = datetime.now(timezone.utc).timestamp()
            await self._r.zremrangebyscore(
                f"{self._prefix}active_challenges_zset", "-inf", now - 300
            )
            result: int = await self._r.zcard(f"{self._prefix}active_challenges_zset")
            return result

        async def add_challenge(
            self,
            req_id: str,
            challenge_bytes: bytes,
            ip: str,
            difficulty: int,
            timestamp: datetime,
            validity_seconds: int,
        ) -> None:
            state = {
                "challenge": challenge_bytes.hex(),
                "ip": ip,
                "timestamp": timestamp.isoformat(),
                "difficulty": difficulty,
            }
            async with self._r.pipeline(transaction=True) as pipe:
                pipe.setex(
                    f"{self._prefix}req:{req_id}",
                    validity_seconds,
                    json.dumps(state),
                )
                pipe.setex(f"{self._prefix}ip:{ip}", validity_seconds, "1")
                pipe.zadd(
                    f"{self._prefix}active_challenges_zset",
                    {req_id: timestamp.timestamp()},
                )
                await pipe.execute()

        async def get_and_delete_challenge(self, req_id: str) -> Optional[ChallengeState]:
            """Atomic get-and-delete via Lua script (prevents replay-attack race)."""
            req_key = f"{self._prefix}req:{req_id}"
            raw: Optional[bytes] = await self._script_get_del(keys=[req_key])
            if not raw:
                return None

            state_dict: dict = json.loads(raw)

            # Clean up ancillary keys (non-critical; best-effort)
            await self._r.delete(f"{self._prefix}ip:{state_dict['ip']}")
            await self._r.zrem(f"{self._prefix}active_challenges_zset", req_id)

            return ChallengeState(
                challenge=bytes.fromhex(state_dict["challenge"]),
                ip=state_dict["ip"],
                timestamp=datetime.fromisoformat(state_dict["timestamp"]),
                difficulty=int(state_dict["difficulty"]),
            )

        async def is_ip_active(self, ip: str) -> bool:
            result: int = await self._r.exists(f"{self._prefix}ip:{ip}")
            return bool(result)

        async def increment_subnet_history(self, subnet: str) -> None:
            key = f"{self._prefix}subnet:{subnet}"
            await self._r.incr(key)
            await self._r.expire(key, 86400)

        async def get_subnet_history(self, subnet: str) -> int:
            val: Optional[bytes] = await self._r.get(f"{self._prefix}subnet:{subnet}")
            return int(val) if val else 0

        async def increment_fingerprint_history(self, fingerprint: str) -> None:
            key = f"{self._prefix}fingerprint:{fingerprint}"
            await self._r.incr(key)
            await self._r.expire(key, 86400)

        async def get_fingerprint_history(self, fingerprint: str) -> int:
            val: Optional[bytes] = await self._r.get(f"{self._prefix}fingerprint:{fingerprint}")
            return int(val) if val else 0

        async def add_global_solve(self, timestamp: datetime) -> None:
            key = f"{self._prefix}global_solves"
            score = timestamp.timestamp()
            # Member must be unique even within the same second; append a random token
            import secrets as _secrets
            member = f"{score}-{_secrets.token_hex(4)}"
            await self._r.zadd(key, {member: score})
            await self._r.zremrangebyscore(key, "-inf", score - 60)

        async def get_recent_global_solves_count(self, window_seconds: int) -> int:
            key = f"{self._prefix}global_solves"
            now = datetime.now(timezone.utc).timestamp()
            result: int = await self._r.zcount(key, now - window_seconds, "+inf")
            return result

except ImportError:

    class RedisStorage:  # type: ignore[no-redef]
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise ImportError(
                "redis-py is not installed. Add `redis[asyncio]` to your dependencies."
            )
