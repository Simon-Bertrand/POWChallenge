import Redis from 'ioredis';

// ──────────────────────────────────────────────────────────────────────────────
// Shared types
// ──────────────────────────────────────────────────────────────────────────────

/** In-flight challenge state kept in storage. */
export interface ChallengeState {
    readonly challenge: Buffer;
    readonly ip: string;
    readonly timestamp: Date;
    readonly difficulty: number;
}

/** Serialised form stored in Redis (all fields JSON-safe). */
interface RedisSerializedState {
    readonly challenge: string; // hex-encoded bytes
    readonly ip: string;
    readonly timestamp: string; // ISO-8601
    readonly difficulty: number;
}

// ──────────────────────────────────────────────────────────────────────────────
// Storage interface
// ──────────────────────────────────────────────────────────────────────────────

/**
 * All storage back-ends must implement this interface.
 * No `any` is permitted; all returns are fully typed.
 */
export interface StorageBackend {
    store_challenge(req_id: string, challenge_bytes: Buffer, ip: string, difficulty: number, timestamp: Date, validity_seconds: number): Promise<void>;
    fetch_challenge(req_id: string): Promise<ChallengeState | null>;
    delete_challenge(req_id: string): Promise<boolean>;
    count_challenges(): Promise<number>;
    is_ip_active(ip: string): Promise<boolean>;
    increment_subnet_history(subnet: string): Promise<void>;
    get_subnet_history(subnet: string): Promise<number>;
    increment_fingerprint_history(fingerprint: string): Promise<void>;
    get_fingerprint_history(fingerprint: string): Promise<number>;
    add_global_solve(timestamp: Date): Promise<void>;
    get_recent_global_solves_count(window_seconds: number): Promise<number>;
}

// ──────────────────────────────────────────────────────────────────────────────
// In-memory implementation
// ──────────────────────────────────────────────────────────────────────────────

export class MemoryStorage implements StorageBackend {
    private readonly active_challenges: Map<string, ChallengeState> = new Map();
    private readonly active_ips: Set<string> = new Set();
    private readonly fingerprint_history: Map<string, number> = new Map();
    private readonly subnet_history: Map<string, number> = new Map();
    private readonly global_solve_history: Date[] = [];
    public max_challenges: number;

    constructor(max_challenges = 10000) {
        this.max_challenges = max_challenges;
    }

    private cleanup_expired(validity_seconds: number): void {
        const now = Date.now();
        const to_delete: string[] = [];
        for (const [req_id, state] of this.active_challenges) {
            if ((now - state.timestamp.getTime()) / 1000 > validity_seconds) {
                to_delete.push(req_id);
            }
        }
        for (const req_id of to_delete) {
            const state = this.active_challenges.get(req_id);
            if (state) {
                this.active_challenges.delete(req_id);
                this.active_ips.delete(state.ip);
            }
        }
    }

    async store_challenge(req_id: string, challenge_bytes: Buffer, ip: string, difficulty: number, timestamp: Date, validity_seconds: number): Promise<void> {
        this.cleanup_expired(validity_seconds);
        if (this.active_challenges.size >= this.max_challenges) {
            throw new Error('Server busy');
        }
        this.active_challenges.set(req_id, { challenge: challenge_bytes, ip, timestamp, difficulty });
        this.active_ips.add(ip);
    }

    async fetch_challenge(req_id: string): Promise<ChallengeState | null> {
        return this.active_challenges.get(req_id) ?? null;
    }

    async delete_challenge(req_id: string): Promise<boolean> {
        const state = this.active_challenges.get(req_id) ?? null;
        if (state) {
            this.active_challenges.delete(req_id);
            this.active_ips.delete(state.ip);
            return true;
        }
        return false;
    }

    async count_challenges(): Promise<number> {
        return this.active_challenges.size;
    }

    async is_ip_active(ip: string): Promise<boolean> {
        return this.active_ips.has(ip);
    }

    private evict_map(map: Map<string, number>, keep = 5000): void {
        if (map.size > 10000) {
            const sorted = [...map.entries()].sort((a, b) => b[1] - a[1]);
            map.clear();
            for (const [k, v] of sorted.slice(0, keep)) map.set(k, v);
        }
    }

    async increment_subnet_history(subnet: string): Promise<void> {
        this.subnet_history.set(subnet, (this.subnet_history.get(subnet) ?? 0) + 1);
        this.evict_map(this.subnet_history);
    }

    async get_subnet_history(subnet: string): Promise<number> {
        return this.subnet_history.get(subnet) ?? 0;
    }

    async increment_fingerprint_history(fingerprint: string): Promise<void> {
        this.fingerprint_history.set(fingerprint, (this.fingerprint_history.get(fingerprint) ?? 0) + 1);
        this.evict_map(this.fingerprint_history);
    }

    async get_fingerprint_history(fingerprint: string): Promise<number> {
        return this.fingerprint_history.get(fingerprint) ?? 0;
    }

    async add_global_solve(timestamp: Date): Promise<void> {
        this.global_solve_history.push(timestamp);
    }

    async get_recent_global_solves_count(window_seconds: number): Promise<number> {
        const cutoff = Date.now() - window_seconds * 1000;
        while (this.global_solve_history.length > 0 && this.global_solve_history[0].getTime() < cutoff) {
            this.global_solve_history.shift();
        }
        return this.global_solve_history.length;
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Redis implementation
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Lua script: atomically GET-then-DEL a key.
 * Eliminates the TOCTOU race window present in a plain pipeline (SEC-1).
 */
const LUA_GET_AND_DELETE = `
local v = redis.call('GET', KEYS[1])
if v then
    redis.call('DEL', KEYS[1])
    return v
end
return false
`;

export class RedisStorage implements StorageBackend {
    private readonly redis: Redis;
    public max_challenges: number;
    private readonly prefix = 'pow_captcha:';

    constructor(redis_url: string, max_challenges = 10000) {
        this.redis = new Redis(redis_url);
        this.max_challenges = max_challenges;
    }

    async count_challenges(): Promise<number> {
        const now = Math.floor(Date.now() / 1000);
        await this.redis.zremrangebyscore(`${this.prefix}active_challenges_zset`, '-inf', now - 300);
        return this.redis.zcard(`${this.prefix}active_challenges_zset`);
    }

    async store_challenge(req_id: string, challenge_bytes: Buffer, ip: string, difficulty: number, timestamp: Date, validity_seconds: number): Promise<void> {
        const state: RedisSerializedState = {
            challenge: challenge_bytes.toString('hex'),
            ip,
            timestamp: timestamp.toISOString(),
            difficulty,
        };
        const pipeline = this.redis.pipeline();
        pipeline.setex(`${this.prefix}req:${req_id}`, validity_seconds, JSON.stringify(state));
        pipeline.setex(`${this.prefix}ip:${ip}`, validity_seconds, '1');
        pipeline.zadd(`${this.prefix}active_challenges_zset`, Math.floor(timestamp.getTime() / 1000), req_id);
        await pipeline.exec();
    }

    async fetch_challenge(req_id: string): Promise<ChallengeState | null> {
        const req_key = `${this.prefix}req:${req_id}`;
        const raw = await this.redis.get(req_key);
        if (!raw) return null;
        const state: RedisSerializedState = JSON.parse(raw);
        return {
            challenge: Buffer.from(state.challenge, 'hex'),
            ip: state.ip,
            timestamp: new Date(state.timestamp),
            difficulty: state.difficulty,
        };
    }

    async delete_challenge(req_id: string): Promise<boolean> {
        // Atomic get-and-delete via Lua script (fixes SEC-1 replay-attack race)
        const req_key = `${this.prefix}req:${req_id}`;
        const raw = await this.redis.eval(LUA_GET_AND_DELETE, 1, req_key) as string | null;
        if (!raw) return false;

        const state: RedisSerializedState = JSON.parse(raw);

        // Best-effort cleanup of ancillary keys (non-critical)
        const pipeline = this.redis.pipeline();
        pipeline.del(`${this.prefix}ip:${state.ip}`);
        pipeline.zrem(`${this.prefix}active_challenges_zset`, req_id);
        await pipeline.exec();
        return true;
    }

    async is_ip_active(ip: string): Promise<boolean> {
        return (await this.redis.exists(`${this.prefix}ip:${ip}`)) === 1;
    }

    async increment_subnet_history(subnet: string): Promise<void> {
        const key = `${this.prefix}subnet:${subnet}`;
        await this.redis.incr(key);
        await this.redis.expire(key, 86400);
    }

    async get_subnet_history(subnet: string): Promise<number> {
        const val = await this.redis.get(`${this.prefix}subnet:${subnet}`);
        return val ? parseInt(val, 10) : 0;
    }

    async increment_fingerprint_history(fingerprint: string): Promise<void> {
        const key = `${this.prefix}fingerprint:${fingerprint}`;
        await this.redis.incr(key);
        await this.redis.expire(key, 86400);
    }

    async get_fingerprint_history(fingerprint: string): Promise<number> {
        const val = await this.redis.get(`${this.prefix}fingerprint:${fingerprint}`);
        return val ? parseInt(val, 10) : 0;
    }

    async add_global_solve(timestamp: Date): Promise<void> {
        const key = `${this.prefix}global_solves`;
        const score = Math.floor(timestamp.getTime() / 1000);
        // Member must be unique even within the same second
        await this.redis.zadd(key, score, `${score}-${Math.random().toString(36).slice(2)}`);
        await this.redis.zremrangebyscore(key, '-inf', score - 60);
    }

    async get_recent_global_solves_count(window_seconds: number): Promise<number> {
        const key = `${this.prefix}global_solves`;
        const now = Math.floor(Date.now() / 1000);
        return this.redis.zcount(key, now - window_seconds, '+inf');
    }
}
