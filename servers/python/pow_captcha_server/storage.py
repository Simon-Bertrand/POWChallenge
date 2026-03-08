import os
from datetime import datetime, timezone
import json
from ipaddress import IPv4Address, IPv6Address
from typing import Optional, Dict

class BaseStorage:
    async def add_challenge(self, req_id: str, challenge_bytes: bytes, ip: str, difficulty: int, timestamp: datetime, validity_seconds: int):
        raise NotImplementedError

    async def get_and_delete_challenge(self, req_id: str) -> Optional[Dict]:
        raise NotImplementedError

    async def count_challenges(self) -> int:
        raise NotImplementedError

    async def is_ip_active(self, ip: str) -> bool:
        raise NotImplementedError

    async def increment_subnet_history(self, subnet: str):
        raise NotImplementedError

    async def get_subnet_history(self, subnet: str) -> int:
        raise NotImplementedError

    async def increment_fingerprint_history(self, fingerprint: str):
        raise NotImplementedError

    async def get_fingerprint_history(self, fingerprint: str) -> int:
        raise NotImplementedError

    async def add_global_solve(self, timestamp: datetime):
        raise NotImplementedError

    async def get_recent_global_solves_count(self, window_seconds: int) -> int:
        raise NotImplementedError


class MemoryStorage(BaseStorage):
    def __init__(self, max_challenges=10000):
        self.active_challenges = {}
        self.active_ips = set()
        import collections
        self.fingerprint_history = collections.Counter()
        self.subnet_history = collections.Counter()
        self.global_solve_history = collections.deque(maxlen=1000)
        self.max_challenges = max_challenges

    def _cleanup_expired(self, validity_seconds):
        now = datetime.now(timezone.utc)
        to_delete = []
        for req_id, state in self.active_challenges.items():
            if (now - state['timestamp']).total_seconds() > validity_seconds:
                to_delete.append(req_id)
        for req_id in to_delete:
            state = self.active_challenges.pop(req_id, None)
            if state and state['ip'] in self.active_ips:
                self.active_ips.discard(state['ip'])

    async def add_challenge(self, req_id: str, challenge_bytes: bytes, ip: str, difficulty: int, timestamp: datetime, validity_seconds: int):
        self._cleanup_expired(validity_seconds)
        if len(self.active_challenges) >= self.max_challenges:
            raise Exception("Server busy")

        self.active_challenges[req_id] = {
            'challenge': challenge_bytes,
            'ip': ip,
            'timestamp': timestamp,
            'difficulty': difficulty
        }
        self.active_ips.add(ip)

    async def get_and_delete_challenge(self, req_id: str) -> Optional[Dict]:
        state = self.active_challenges.pop(req_id, None)
        if state and state['ip'] in self.active_ips:
            self.active_ips.discard(state['ip'])
        return state

    async def count_challenges(self) -> int:
        return len(self.active_challenges)

    async def is_ip_active(self, ip: str) -> bool:
        return ip in self.active_ips

    async def increment_subnet_history(self, subnet: str):
        self.subnet_history[subnet] += 1
        if len(self.subnet_history) > 10000:
            most_common = self.subnet_history.most_common(5000)
            self.subnet_history.clear()
            self.subnet_history.update(dict(most_common))

    async def get_subnet_history(self, subnet: str) -> int:
        return self.subnet_history.get(subnet, 0)

    async def increment_fingerprint_history(self, fingerprint: str):
        self.fingerprint_history[fingerprint] += 1
        if len(self.fingerprint_history) > 10000:
            most_common = self.fingerprint_history.most_common(5000)
            self.fingerprint_history.clear()
            self.fingerprint_history.update(dict(most_common))

    async def get_fingerprint_history(self, fingerprint: str) -> int:
        return self.fingerprint_history.get(fingerprint, 0)

    async def add_global_solve(self, timestamp: datetime):
        self.global_solve_history.append(timestamp)

    async def get_recent_global_solves_count(self, window_seconds: int) -> int:
        now = datetime.now(timezone.utc)
        while self.global_solve_history and (now - self.global_solve_history[0]).total_seconds() > window_seconds:
            self.global_solve_history.popleft()
        return len(self.global_solve_history)

try:
    import redis.asyncio as redis
    class RedisStorage(BaseStorage):
        def __init__(self, redis_url: str, max_challenges=10000):
            self.r = redis.from_url(redis_url)
            self.max_challenges = max_challenges
            self.prefix = "pow_captcha:"

        async def count_challenges(self) -> int:
            # Use ZCARD on a sorted set of active challenges to get O(1) count
            # Clean up expired ones lazily before counting
            now = datetime.now(timezone.utc).timestamp()
            await self.r.zremrangebyscore(f"{self.prefix}active_challenges_zset", '-inf', now - 300) # 300s is max validity
            return await self.r.zcard(f"{self.prefix}active_challenges_zset")

        async def add_challenge(self, req_id: str, challenge_bytes: bytes, ip: str, difficulty: int, timestamp: datetime, validity_seconds: int):
            state = {
                'challenge': challenge_bytes.hex(),
                'ip': ip,
                'timestamp': timestamp.isoformat(),
                'difficulty': difficulty
            }
            # Use a pipeline to ensure atomic creation
            async with self.r.pipeline(transaction=True) as pipe:
                pipe.setex(f"{self.prefix}req:{req_id}", validity_seconds, json.dumps(state))
                # Track active IP
                pipe.setex(f"{self.prefix}ip:{ip}", validity_seconds, "1")
                # Add to ZSET for capacity tracking
                pipe.zadd(f"{self.prefix}active_challenges_zset", {req_id: timestamp.timestamp()})
                await pipe.execute()

        async def get_and_delete_challenge(self, req_id: str) -> Optional[Dict]:
            # Atomic get and delete
            async with self.r.pipeline(transaction=True) as pipe:
                pipe.get(f"{self.prefix}req:{req_id}")
                pipe.delete(f"{self.prefix}req:{req_id}")
                pipe.zrem(f"{self.prefix}active_challenges_zset", req_id)
                results = await pipe.execute()

            data = results[0]
            if not data:
                return None

            state = json.loads(data)
            state['challenge'] = bytes.fromhex(state['challenge'])
            state['timestamp'] = datetime.fromisoformat(state['timestamp'])

            # Remove IP from active set
            await self.r.delete(f"{self.prefix}ip:{state['ip']}")
            return state

        async def is_ip_active(self, ip: str) -> bool:
            return bool(await self.r.exists(f"{self.prefix}ip:{ip}"))

        async def increment_subnet_history(self, subnet: str):
            key = f"{self.prefix}subnet:{subnet}"
            await self.r.incr(key)
            await self.r.expire(key, 86400) # Keep history for 1 day

        async def get_subnet_history(self, subnet: str) -> int:
            val = await self.r.get(f"{self.prefix}subnet:{subnet}")
            return int(val) if val else 0

        async def increment_fingerprint_history(self, fingerprint: str):
            key = f"{self.prefix}fingerprint:{fingerprint}"
            await self.r.incr(key)
            await self.r.expire(key, 86400)

        async def get_fingerprint_history(self, fingerprint: str) -> int:
            val = await self.r.get(f"{self.prefix}fingerprint:{fingerprint}")
            return int(val) if val else 0

        async def add_global_solve(self, timestamp: datetime):
            # Use Redis Time Series or a simple list/ZSET
            key = f"{self.prefix}global_solves"
            score = timestamp.timestamp()
            await self.r.zadd(key, {str(score): score})
            # Prune old
            await self.r.zremrangebyscore(key, '-inf', score - 60)

        async def get_recent_global_solves_count(self, window_seconds: int) -> int:
            key = f"{self.prefix}global_solves"
            now = datetime.now(timezone.utc).timestamp()
            return await self.r.zcount(key, now - window_seconds, '+inf')

except ImportError:
    class RedisStorage(BaseStorage):
        def __init__(self, *args, **kwargs):
            raise ImportError("redis-py is not installed. Run `pip install redis`")
