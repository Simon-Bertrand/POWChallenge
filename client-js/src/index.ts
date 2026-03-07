/**
 * Argon2id Proof of Work — Client Library
 * GPU-hostile memory-hard hashing (time=1, mem=19 MiB, parallelism=1, hashLen=32)
 */

/* eslint-disable @typescript-eslint/no-var-requires */

// ──────────────────────────────────────────────────────────────────────────────
// Argon2id parameters (must stay in sync with all server implementations)
// ──────────────────────────────────────────────────────────────────────────────
const ARGON2_TIME = 1;
const ARGON2_MEM = 19456;       // KiB — 19 MiB, GPU-hostile
const ARGON2_PARALLELISM = 1;
const ARGON2_HASH_LEN = 32;
const ARGON2_TYPE = 2;          // ArgonType.Argon2id

// CDN URL used by the Web Worker (cannot bundle WASM inside a Worker blob)
const ARGON2_CDN = 'https://cdn.jsdelivr.net/npm/argon2-browser@1.18.0/dist/argon2-bundled.min.js';

// ──────────────────────────────────────────────────────────────────────────────
// Cross-platform WASM loading
// ──────────────────────────────────────────────────────────────────────────────

// Load WASM as base64 via custom webpack loader
const wasmBase64: string = require('argon2-browser/dist/argon2.wasm');

function base64ToBytes(b64: string): Uint8Array {
    if (typeof Buffer !== 'undefined') {
        return new Uint8Array(Buffer.from(b64, 'base64'));
    }
    const bStr = atob(b64);
    const bytes = new Uint8Array(bStr.length);
    for (let i = 0; i < bStr.length; i++) bytes[i] = bStr.charCodeAt(i);
    return bytes;
}

// Ensure `self` exists in Node.js environments where it is undefined by default
if (typeof self === 'undefined') {
    (globalThis as { self?: typeof globalThis }).self = globalThis;
}

type ArgonGlobal = {
    Module?: { wasmBinary?: Uint8Array };
};

const _g = self as unknown as ArgonGlobal;
_g.Module = _g.Module ?? {};
_g.Module.wasmBinary = base64ToBytes(wasmBase64);

// ──────────────────────────────────────────────────────────────────────────────
// Argon2 wrapper types
// ──────────────────────────────────────────────────────────────────────────────

interface Argon2HashOptions {
    pass: Uint8Array;
    salt: Uint8Array;
    time: number;
    mem: number;
    hashLen: number;
    parallelism: number;
    type: number;
}

interface Argon2HashResult {
    hash: Uint8Array;
}

interface Argon2Module {
    hash(opts: Argon2HashOptions): Promise<Argon2HashResult>;
}

const argon2: Argon2Module = require('argon2-browser');

// ──────────────────────────────────────────────────────────────────────────────
// Web Worker message types
// ──────────────────────────────────────────────────────────────────────────────

interface WorkerRequest {
    challenge: Uint8Array;
    nonce: Uint8Array;
    difficulty: number;
    id: string;
}

interface WorkerSuccess {
    id: string;
    nonce: Uint8Array;
    success: true;
}

interface WorkerFailure {
    id: string;
    error: string;
    success: false;
}

type WorkerResponse = WorkerSuccess | WorkerFailure;

// ──────────────────────────────────────────────────────────────────────────────
// Core PoW class
// ──────────────────────────────────────────────────────────────────────────────

class ProofOfWork {
    async argon2id(nonce: Uint8Array, challenge: Uint8Array): Promise<Uint8Array> {
        const result = await argon2.hash({
            pass: nonce,
            salt: challenge,
            time: ARGON2_TIME,
            mem: ARGON2_MEM,
            hashLen: ARGON2_HASH_LEN,
            parallelism: ARGON2_PARALLELISM,
            type: ARGON2_TYPE,
        });
        return result.hash;
    }

    /**
     * Return `true` if the first `difficultyBits` bits of `hash` are all zero.
     */
    validatePOW(hash: Uint8Array, difficultyBits: number): boolean {
        for (let i = 0; i < ARGON2_HASH_LEN; i++) {
            const bitsToCheck = Math.max(0, Math.min(8, difficultyBits - i * 8));
            if (bitsToCheck === 0) break;
            if ((hash[i] & ((0xFF << (8 - bitsToCheck)) & 0xFF)) !== 0) return false;
        }
        return true;
    }

    /** Increment `nonce` in-place (little-endian counter). */
    incrementNonce(nonce: Uint8Array): void {
        for (let i = 0; i < nonce.length; i++) {
            nonce[i] = (nonce[i] + 1) & 0xFF;
            if (nonce[i] !== 0) break;
        }
    }

    /** Mine until a valid nonce is found. Yields the event loop every 10 iterations. */
    async minePOW(challenge: Uint8Array, nonce: Uint8Array, difficulty: number): Promise<Uint8Array> {
        let iterations = 0;
        while (true) {
            const hash = await this.argon2id(nonce, challenge);
            if (this.validatePOW(hash, difficulty)) return new Uint8Array(nonce);
            this.incrementNonce(nonce);
            iterations++;
            if (iterations % 10 === 0) await new Promise<void>(r => setTimeout(r, 0));
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Web Worker inline script (off-loads mining to a separate thread)
// ──────────────────────────────────────────────────────────────────────────────

const workerScript = `
importScripts('${ARGON2_CDN}');
const ARGON2_TIME=${ARGON2_TIME},ARGON2_MEM=${ARGON2_MEM},ARGON2_PARALLELISM=${ARGON2_PARALLELISM},ARGON2_HASH_LEN=${ARGON2_HASH_LEN},ARGON2_TYPE=${ARGON2_TYPE};
async function argon2id(nonce,challenge){
    return (await argon2.hash({pass:nonce,salt:challenge,time:ARGON2_TIME,mem:ARGON2_MEM,hashLen:ARGON2_HASH_LEN,parallelism:ARGON2_PARALLELISM,type:ARGON2_TYPE})).hash;
}
function validatePOW(hash,bits){
    for(let i=0;i<ARGON2_HASH_LEN;i++){const b=Math.max(0,Math.min(8,bits-i*8));if(b===0)break;if((hash[i]&((0xFF<<(8-b))&0xFF))!==0)return false;}return true;
}
function incrementNonce(n){for(let i=0;i<n.length;i++){n[i]=(n[i]+1)&0xFF;if(n[i]!==0)break;}}
async function minePOW(challenge,nonce,difficulty){
    while(true){const h=await argon2id(nonce,challenge);if(validatePOW(h,difficulty))return new Uint8Array(nonce);incrementNonce(nonce);}
}
self.onmessage=async function(e){
    const{challenge,nonce,difficulty,id}=e.data;
    try{self.postMessage({id,nonce:await minePOW(challenge,nonce,difficulty),success:true});}
    catch(err){self.postMessage({id,error:err.message||String(err),success:false});}
};
`;

// ──────────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────────

/** Mine using a Web Worker when available; falls back to main thread. */
export async function minePOWWithWorker(challenge: Uint8Array, difficulty: number): Promise<Uint8Array> {
    if (typeof window === 'undefined' || !window.Worker) {
        const pow = new ProofOfWork();
        const nonce = new Uint8Array(32);
        if (globalThis.crypto) globalThis.crypto.getRandomValues(nonce);
        else for (let i = 0; i < 32; i++) nonce[i] = Math.floor(Math.random() * 256);
        return pow.minePOW(challenge, nonce, difficulty);
    }
    return new Promise<Uint8Array>((resolve, reject) => {
        const blob = new Blob([workerScript], { type: 'application/javascript' });
        const workerUrl = URL.createObjectURL(blob);
        const worker = new Worker(workerUrl);
        const nonce = new Uint8Array(32);
        window.crypto.getRandomValues(nonce);
        const id = Math.random().toString(36).slice(2, 11);

        worker.onmessage = (e: MessageEvent<WorkerResponse>) => {
            if (e.data.id !== id) return;
            if (e.data.success) {
                resolve(e.data.nonce);
            } else {
                reject(new Error(e.data.error));
            }
            worker.terminate();
            URL.revokeObjectURL(workerUrl);
        };

        worker.onerror = (err: ErrorEvent) => {
            reject(err);
            worker.terminate();
            URL.revokeObjectURL(workerUrl);
        };

        const msg: WorkerRequest = { challenge, nonce, difficulty, id };
        worker.postMessage(msg);
    });
}

/** Namespace exported to the global scope for browser consumption. */
interface WebCryptoHashNamespace {
    ProofOfWork: typeof ProofOfWork;
    minePOWWithWorker: typeof minePOWWithWorker;
    ARGON2_CDN: string;
    ARGON2_TIME: number;
    ARGON2_MEM: number;
    ARGON2_PARALLELISM: number;
    ARGON2_HASH_LEN: number;
}

const globalScope = (
    typeof window !== 'undefined' ? window :
        typeof self !== 'undefined' ? self :
            globalThis
) as typeof globalThis & { WebCryptoHash?: WebCryptoHashNamespace };

globalScope.WebCryptoHash = {
    ProofOfWork,
    minePOWWithWorker,
    ARGON2_CDN,
    ARGON2_TIME,
    ARGON2_MEM,
    ARGON2_PARALLELISM,
    ARGON2_HASH_LEN,
};
