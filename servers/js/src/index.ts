import * as crypto from 'crypto';
import * as argon2 from 'argon2';
import { v7 as uuidv7 } from 'uuid';
import { Address4, Address6 } from 'ip-address';
import { StorageBackend, MemoryStorage, RedisStorage, ChallengeState } from './storage';
export { StorageBackend, MemoryStorage, RedisStorage, ChallengeState };

// ──────────────────────────────────────────────────────────────────────────────
// Argon2id parameters — must stay in sync with client-js and all other servers
// ──────────────────────────────────────────────────────────────────────────────
const ARGON2_TIME_COST = 1;
const ARGON2_MEMORY_COST = 19456; // KiB — 19 MiB, GPU-hostile
const ARGON2_PARALLELISM = 1;
const ARGON2_HASH_LEN = 32;

/**
 * Maximum decoded nonce length (bytes).  Client always sends 32 bytes; we allow
 * up to 64 to be future-proof, but cap here to prevent Argon2 DoS (SEC-3).
 */
const NONCE_MAX_BYTES = 64;

// ──────────────────────────────────────────────────────────────────────────────
// Domain errors
// ──────────────────────────────────────────────────────────────────────────────

export class POWCaptchaError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'POWCaptchaError';
    }
}

export class ChallengeNotFoundOrExpired extends POWCaptchaError {
    constructor() { super('Challenge not found or expired'); }
}

export class DifficultyMismatch extends POWCaptchaError {
    constructor() { super('Difficulty mismatch'); }
}

export class InvalidProofOfWork extends POWCaptchaError {
    constructor() { super('Invalid Proof of Work'); }
}

export class ChallengeAlreadyActive extends POWCaptchaError {
    constructor() { super('Challenge already active'); }
}

export class ServerBusy extends POWCaptchaError {
    constructor() { super('Server busy, try again later'); }
}

// ──────────────────────────────────────────────────────────────────────────────
// Wire-format types
// ──────────────────────────────────────────────────────────────────────────────

/** Response returned by GET /challenge. */
export interface CaptchaResponse {
    readonly challenge: string;
    readonly difficulty: number;
    readonly req_id: string;
}

/** Request body accepted by POST /verify. */
export interface CaptchaValidatedPOW {
    readonly req_id: string;
    readonly challenge: string;
    readonly timestamp: string;
    readonly difficulty: number;
    readonly nonce: string;
}

// ──────────────────────────────────────────────────────────────────────────────
// Server
// ──────────────────────────────────────────────────────────────────────────────

export class POWCaptchaServer {
    private readonly storage: StorageBackend;
    private readonly default_difficulty: number;
    private readonly validity_seconds: number;
    private readonly enable_fingerprint: boolean;
    private readonly request_minimum_delay: number | null;
    private readonly cookie_ttl: number;
    private readonly enable_dynamic_difficulty: boolean;
    private readonly server_secret: Buffer;
    private max_active_challenges: number;

    constructor(
        default_difficulty: number,
        validity_seconds = 300,
        enable_fingerprint = false,
        request_minimum_delay: number | null = null,
        cookie_ttl = 3600,
        storage?: StorageBackend,
        enable_dynamic_difficulty = true
    ) {
        this.default_difficulty = default_difficulty;
        this.validity_seconds = validity_seconds;
        this.enable_fingerprint = enable_fingerprint;
        this.request_minimum_delay = request_minimum_delay;
        this.cookie_ttl = cookie_ttl;
        this.enable_dynamic_difficulty = enable_dynamic_difficulty;
        this.server_secret = crypto.randomBytes(64);
        this.max_active_challenges = 10000;

        if (storage) {
            this.storage = storage;
        } else {
            const redis_url = process.env['POW_REDIS_URL'];
            this.storage = redis_url
                ? new RedisStorage(redis_url, this.max_active_challenges)
                : new MemoryStorage(this.max_active_challenges);
        }
    }

    /** Update the cap on simultaneous in-flight challenges. Propagates to storage. */
    set_max_active_challenges(max: number): void {
        this.max_active_challenges = max;
        // Propagate to whichever concrete storage is active (SEC-6)
        (this.storage as MemoryStorage | RedisStorage).max_challenges = max;
    }

    // ── Clearance token ────────────────────────────────────────────────────

    private generate_client_hash(ip: string, user_agent: string, fingerprint: string): string {
        return crypto.createHash('sha256').update(`${ip}|${user_agent}|${fingerprint}`).digest('hex');
    }

    generate_clearance_token(ip: string, user_agent: string, fingerprint: string): string {
        const exp = Math.floor(Date.now() / 1000) + this.cookie_ttl;
        const client_hash = this.generate_client_hash(ip, user_agent, fingerprint);
        const payload = `${exp}:${client_hash}`;
        const signature = crypto.createHmac('sha256', this.server_secret).update(payload).digest('hex');
        return `${payload}:${signature}`;
    }

    validate_clearance_token(token: string, ip: string, user_agent: string, fingerprint: string): boolean {
        const parts = token.split(':');
        if (parts.length !== 3) return false;
        const [exp_str, hash_str, sig_str] = parts;

        const exp = parseInt(exp_str, 10);
        if (isNaN(exp) || Math.floor(Date.now() / 1000) > exp) return false;

        const expected_hash = this.generate_client_hash(ip, user_agent, fingerprint);
        const exp_hash_buf = Buffer.from(expected_hash, 'utf8');
        const act_hash_buf = Buffer.from(hash_str, 'utf8');
        if (exp_hash_buf.length !== act_hash_buf.length || !crypto.timingSafeEqual(exp_hash_buf, act_hash_buf)) return false;

        const payload = `${exp_str}:${hash_str}`;
        const expected_sig = crypto.createHmac('sha256', this.server_secret).update(payload).digest('hex');
        const exp_sig_buf = Buffer.from(expected_sig, 'utf8');
        const act_sig_buf = Buffer.from(sig_str, 'utf8');
        return exp_sig_buf.length === act_sig_buf.length && crypto.timingSafeEqual(exp_sig_buf, act_sig_buf);
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private static b64_encode(b: Buffer): string {
        return b.toString('base64');
    }

    private static b64_decode(s: string): Buffer {
        return Buffer.from(s, 'base64');
    }

    /**
     * Normalise IPv4-mapped IPv6 (::ffff:1.2.3.4 → 1.2.3.4) and return the /24
     * (IPv4) or /48 (IPv6) subnet prefix for rate-limiting (SEC-5).
     */
    private static get_subnet_prefix(raw_ip: string): string {
        // Unwrap IPv4-mapped IPv6 (::ffff:1.2.3.4 → 1.2.3.4) — SEC-5
        const mapped_match = raw_ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
        const ip = mapped_match ? mapped_match[1] : raw_ip;

        if (Address4.isValid(ip)) {
            return ip.split('.').slice(0, 3).join('.');
        }
        if (Address6.isValid(ip)) {
            return ip.split(':').slice(0, 3).join(':');
        }
        return ip;
    }

    private static validate_pow_hash(h: Buffer, difficulty_bits: number): boolean {
        for (let i = 0; i < ARGON2_HASH_LEN; i++) {
            const bits_to_check = Math.max(0, Math.min(8, difficulty_bits - i * 8));
            if (bits_to_check === 0) break;
            const mask = (0xFF << (8 - bits_to_check)) & 0xFF;
            if ((h[i] & mask) !== 0) return false;
        }
        return true;
    }

    // ── Core API ───────────────────────────────────────────────────────────

    async get_challenge(client_ip: string, fingerprint: string | null = null): Promise<CaptchaResponse> {
        const now = new Date();

        if (await this.storage.is_ip_active(client_ip)) throw new ChallengeAlreadyActive();
        if (await this.storage.count_challenges() >= this.max_active_challenges) throw new ServerBusy();

        let dynamic_difficulty = this.default_difficulty;

        if (this.enable_dynamic_difficulty) {
            const subnet_prefix = POWCaptchaServer.get_subnet_prefix(client_ip);
            const subnet_history = await this.storage.get_subnet_history(subnet_prefix);
            const subnet_boost = Math.floor(subnet_history / 5);
            dynamic_difficulty += subnet_boost;

            if (this.enable_fingerprint && fingerprint) {
                const fp_history = await this.storage.get_fingerprint_history(fingerprint);
                dynamic_difficulty += Math.floor(fp_history / 5);
            }

            const recent_global = await this.storage.get_recent_global_solves_count(300);
            const global_boost = recent_global > 1000 ? Math.floor((recent_global - 1000) / 50) : 0;
            dynamic_difficulty += global_boost;

            console.log(`[POW] IP: ${client_ip} Subnet: ${subnet_prefix} History: ${subnet_history} (Boost: ${subnet_boost}) Global: ${recent_global} (Boost: ${global_boost}) Base: ${this.default_difficulty} Final: ${dynamic_difficulty}`);
        }

        const ip_salt = crypto.createHash('sha256').update(client_ip).update(this.server_secret).digest();
        const challenge_bytes = Buffer.concat([crypto.randomBytes(16), ip_salt.subarray(0, 16)]);
        const req_id = uuidv7();

        try {
            await this.storage.store_challenge(req_id, challenge_bytes, client_ip, dynamic_difficulty, now, this.validity_seconds);
        } catch {
            throw new ServerBusy();
        }

        return {
            challenge: POWCaptchaServer.b64_encode(challenge_bytes),
            difficulty: dynamic_difficulty,
            req_id,
        };
    }

    async verify_pow(request: CaptchaValidatedPOW, client_ip: string, fingerprint: string | null = null): Promise<boolean> {
        const query_start = Date.now();

        // SEC-3: pre-check base64 nonce length BEFORE consuming the challenge.
        // 64 bytes → 88 base64 chars max. Reject early so the challenge survives.
        const NONCE_MAX_B64_LEN = 88;
        if (request.nonce && request.nonce.length > NONCE_MAX_B64_LEN) {
            throw new InvalidProofOfWork();
        }

        const state: ChallengeState | null = await this.storage.fetch_challenge(request.req_id);
        if (!state) throw new ChallengeNotFoundOrExpired();

        const deleted = await this.storage.delete_challenge(request.req_id);
        if (!deleted) throw new ChallengeNotFoundOrExpired();

        if (state.ip !== client_ip) throw new ChallengeNotFoundOrExpired();
        if ((Date.now() - state.timestamp.getTime()) / 1000 > this.validity_seconds) throw new ChallengeNotFoundOrExpired();
        if (request.difficulty !== state.difficulty) throw new DifficultyMismatch();

        let challenge_bytes: Buffer;
        let nonce_bytes: Buffer;
        try {
            challenge_bytes = POWCaptchaServer.b64_decode(request.challenge);
            nonce_bytes = POWCaptchaServer.b64_decode(request.nonce);
        } catch {
            throw new InvalidProofOfWork();
        }

        // SEC-3: guard against oversized nonce DoS
        if (nonce_bytes.length > NONCE_MAX_BYTES) throw new InvalidProofOfWork();

        if (
            challenge_bytes.length !== state.challenge.length ||
            !crypto.timingSafeEqual(challenge_bytes, state.challenge)
        ) throw new InvalidProofOfWork();

        const computed_hash = await argon2.hash(nonce_bytes, {
            salt: challenge_bytes,
            type: argon2.argon2id,
            timeCost: ARGON2_TIME_COST,
            memoryCost: ARGON2_MEMORY_COST,
            parallelism: ARGON2_PARALLELISM,
            hashLength: ARGON2_HASH_LEN,
            raw: true,
        }) as Buffer;

        if (!POWCaptchaServer.validate_pow_hash(computed_hash, state.difficulty)) throw new InvalidProofOfWork();

        await this.storage.add_global_solve(new Date());
        const subnet_prefix = POWCaptchaServer.get_subnet_prefix(client_ip);
        await this.storage.increment_subnet_history(subnet_prefix);
        if (this.enable_fingerprint && fingerprint) {
            await this.storage.increment_fingerprint_history(fingerprint);
        }

        if (this.request_minimum_delay !== null) {
            const elapsed = (Date.now() - query_start) / 1000;
            if (elapsed < this.request_minimum_delay) {
                await new Promise<void>(r => setTimeout(r, (this.request_minimum_delay! - elapsed) * 1000));
            }
        }

        return true;
    }
}
