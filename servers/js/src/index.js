"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const crypto = __importStar(require("crypto"));
const uuid_1 = require("uuid");
const ip_address_1 = require("ip-address");
const readline = __importStar(require("readline"));
// --- Error Classes ---
class POWCaptchaError extends Error {
    constructor(message) {
        super(message);
        this.name = 'POWCaptchaError';
    }
}
class ChallengeNotFoundOrExpired extends POWCaptchaError {
    constructor() {
        super("Challenge not found or expired");
    }
}
class DifficultyMismatch extends POWCaptchaError {
    constructor() {
        super("Difficulty mismatch");
    }
}
class InvalidProofOfWork extends POWCaptchaError {
    constructor() {
        super("Invalid Proof of Work");
    }
}
class ChallengeAlreadyActive extends POWCaptchaError {
    constructor() {
        super("Challenge already active");
    }
}
class ServerBusy extends POWCaptchaError {
    constructor() {
        super("Server busy, try again later");
    }
}
// --- Server Class ---
class POWCaptchaServer {
    constructor(default_difficulty, validity_seconds = 300, enable_fingerprint = false, request_minimum_delay = null) {
        this.active_challenges = new Map();
        this.active_ips = new Set();
        this.fingerprint_history = new Map();
        this.subnet_history = new Map();
        this.global_solve_history = [];
        this.default_difficulty = default_difficulty;
        this.validity_seconds = validity_seconds;
        this.enable_fingerprint = enable_fingerprint;
        this.request_minimum_delay = request_minimum_delay;
        this.last_cleanup = new Date();
        this.server_secret = crypto.randomBytes(64);
        this.max_active_challenges = 10000;
    }
    setMaxActiveChallenges(max) {
        this.max_active_challenges = max;
    }
    _cleanup_expired(now) {
        this.last_cleanup = now;
        const to_delete = [];
        for (const [req_id, state] of this.active_challenges) {
            if ((now.getTime() - state.timestamp.getTime()) / 1000 > this.validity_seconds) {
                to_delete.push(req_id);
            }
        }
        for (const req_id of to_delete) {
            const state = this.active_challenges.get(req_id);
            if (state) {
                this.active_challenges.delete(req_id);
                if (this.active_ips.has(state.ip)) {
                    this.active_ips.delete(state.ip);
                }
            }
        }
    }
    static _b64url_encode(b) {
        return b.toString('base64url');
    }
    static _b64url_decode(s) {
        return Buffer.from(s, 'base64url');
    }
    static _get_subnet_prefix(ip) {
        if (ip_address_1.Address4.isValid(ip)) {
            const parts = ip.split('.');
            return parts.slice(0, 3).join('.');
        }
        else if (ip_address_1.Address6.isValid(ip)) {
            const parts = ip.split(':');
            return parts.slice(0, 3).join(':');
        }
        return ip; // Fallback
    }
    get_challenge(client_ip, fingerprint = null) {
        const now = new Date();
        if ((now.getTime() - this.last_cleanup.getTime()) / 1000 > 60) {
            this._cleanup_expired(now);
        }
        if (this.active_ips.has(client_ip)) {
            throw new ChallengeAlreadyActive();
        }
        if (this.active_challenges.size >= this.max_active_challenges) {
            this._cleanup_expired(now);
            if (this.active_challenges.size >= this.max_active_challenges) {
                throw new ServerBusy();
            }
        }
        this.active_ips.add(client_ip);
        let dynamic_difficulty = this.default_difficulty;
        const subnet_prefix = POWCaptchaServer._get_subnet_prefix(client_ip);
        const subnet_count = this.subnet_history.get(subnet_prefix) || 0;
        dynamic_difficulty += Math.floor(subnet_count / 5);
        if (this.enable_fingerprint && fingerprint) {
            const count = this.fingerprint_history.get(fingerprint) || 0;
            dynamic_difficulty += Math.floor(count / 5);
        }
        // Global Panic Mode
        // Prune old
        while (this.global_solve_history.length > 0 && (now.getTime() - this.global_solve_history[0].getTime()) / 1000 > 60) {
            this.global_solve_history.shift();
        }
        const recent_global_solves = this.global_solve_history.length;
        if (recent_global_solves > 50) {
            const panic_penalty = Math.floor((recent_global_solves - 50) / 10);
            dynamic_difficulty += panic_penalty;
        }
        const hasher = crypto.createHash('sha256');
        hasher.update(client_ip);
        hasher.update(this.server_secret);
        const ip_salt = hasher.digest();
        // challenge bytes: 16 random + 16 salt
        const random_bytes = crypto.randomBytes(16);
        const challenge_bytes = Buffer.concat([
            random_bytes,
            ip_salt.subarray(0, 16)
        ]);
        const req_id = (0, uuid_1.v7)();
        const state = {
            challenge: challenge_bytes,
            ip: client_ip,
            timestamp: now,
            difficulty: dynamic_difficulty,
            req_id: req_id
        };
        this.active_challenges.set(req_id, state);
        return {
            challenge: POWCaptchaServer._b64url_encode(challenge_bytes),
            difficulty: dynamic_difficulty,
            req_id: req_id
        };
    }
    static validate_pow_hash(h, difficulty_bits) {
        for (let i = 0; i < 32; i++) {
            const bits_to_keep = Math.max(0, Math.min(8, difficulty_bits - i * 8));
            if (bits_to_keep === 0)
                continue;
            const mask = (0xFF << (8 - bits_to_keep)) & 0xFF;
            if ((h[i] & mask) !== 0) {
                return false;
            }
        }
        return true;
    }
    async validate_pow(request, client_ip, fingerprint = null) {
        const query_start = new Date();
        const state = this.active_challenges.get(request.req_id);
        // Always remove immediately
        if (state) {
            this.active_challenges.delete(request.req_id);
            if (this.active_ips.has(state.ip)) {
                this.active_ips.delete(state.ip);
            }
        }
        else {
            throw new ChallengeNotFoundOrExpired();
        }
        const now = new Date();
        if ((now.getTime() - state.timestamp.getTime()) / 1000 > this.validity_seconds) {
            throw new ChallengeNotFoundOrExpired();
        }
        if (request.difficulty !== state.difficulty) {
            throw new DifficultyMismatch();
        }
        let challenge_bytes;
        let nonce_bytes;
        try {
            challenge_bytes = POWCaptchaServer._b64url_decode(request.challenge);
            nonce_bytes = POWCaptchaServer._b64url_decode(request.nonce);
        }
        catch (e) {
            throw new InvalidProofOfWork();
        }
        if (Buffer.compare(challenge_bytes, state.challenge) !== 0) {
            throw new InvalidProofOfWork();
        }
        const hasher = crypto.createHash('sha256');
        hasher.update(challenge_bytes);
        hasher.update(nonce_bytes);
        const computed_hash = hasher.digest();
        if (!POWCaptchaServer.validate_pow_hash(computed_hash, state.difficulty)) {
            throw new InvalidProofOfWork();
        }
        this.global_solve_history.push(new Date());
        const subnet_prefix = POWCaptchaServer._get_subnet_prefix(client_ip);
        this.subnet_history.set(subnet_prefix, (this.subnet_history.get(subnet_prefix) || 0) + 1);
        if (this.subnet_history.size > 10000) {
            // Sort by count desc
            const sorted = Array.from(this.subnet_history.entries()).sort((a, b) => b[1] - a[1]);
            this.subnet_history.clear();
            for (const [k, v] of sorted.slice(0, 5000)) {
                this.subnet_history.set(k, v);
            }
        }
        if (this.enable_fingerprint && fingerprint) {
            this.fingerprint_history.set(fingerprint, (this.fingerprint_history.get(fingerprint) || 0) + 1);
            if (this.fingerprint_history.size > 10000) {
                const sorted = Array.from(this.fingerprint_history.entries()).sort((a, b) => b[1] - a[1]);
                this.fingerprint_history.clear();
                for (const [k, v] of sorted.slice(0, 5000)) {
                    this.fingerprint_history.set(k, v);
                }
            }
        }
        if (this.request_minimum_delay !== null) {
            const elapsed = (new Date().getTime() - query_start.getTime()) / 1000;
            if (elapsed < this.request_minimum_delay) {
                await new Promise(resolve => setTimeout(resolve, (this.request_minimum_delay - elapsed) * 1000));
            }
        }
        return true;
    }
}
// --- Main CLI Loop ---
async function main() {
    const server = new POWCaptchaServer(10, 300, false, null);
    // Use manual line reading from stdin to ensure we handle EOF properly
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
        terminal: false
    });
    for await (const line of rl) {
        if (!line.trim())
            continue;
        try {
            const cmd = JSON.parse(line);
            if (cmd.action === 'get_challenge') {
                const params = cmd.params || {};
                const ip = params.ip || '127.0.0.1';
                const fingerprint = params.fingerprint || null;
                try {
                    const resp = server.get_challenge(ip, fingerprint);
                    console.log(JSON.stringify({ result: resp }));
                }
                catch (e) {
                    console.log(JSON.stringify({ error: e.message }));
                }
            }
            else if (cmd.action === 'validate_pow') {
                const params = cmd.params || {};
                const request = params.request;
                const ip = params.ip || '127.0.0.1';
                const fingerprint = params.fingerprint || null;
                try {
                    const valid = await server.validate_pow(request, ip, fingerprint);
                    console.log(JSON.stringify({ result: { valid } }));
                }
                catch (e) {
                    console.log(JSON.stringify({ error: e.message }));
                }
            }
            else if (cmd.action === 'set_max_active') {
                const params = cmd.params || {};
                const max = params.max;
                server.setMaxActiveChallenges(max);
                console.log(JSON.stringify({ result: { ok: true } }));
            }
            else {
                console.log(JSON.stringify({ error: `Unknown action: ${cmd.action}` }));
            }
        }
        catch (e) {
            console.log(JSON.stringify({ error: `Invalid JSON: ${e.message}` }));
        }
    }
}
if (require.main === module) {
    main();
}
