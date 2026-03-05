const { spawn } = require('child_process');
const crypto = require('crypto');
const path = require('path');
const net = require('net');

const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const RESET = '\x1b[0m';
const ok = (msg) => `${GREEN}[SUCCESS]${RESET} ${msg}`;
const fail = (msg) => `${RED}[FAILED]${RESET} ${msg}`;

// Node.js fallback for WebCrypto
if (!globalThis.crypto) {
    globalThis.crypto = crypto.webcrypto;
}

const nativeArgon2 = require(path.resolve(__dirname, '../servers/js/node_modules/argon2'));
global.argon2 = {
    ArgonType: { Argon2d: 0, Argon2i: 1, Argon2id: 2 },
    hash: async function ({ pass, salt, time, mem, hashLen, parallelism, type }) {
        const argon2Types = [nativeArgon2.argon2d, nativeArgon2.argon2i, nativeArgon2.argon2id];
        const hash = await nativeArgon2.hash(Buffer.from(pass), {
            salt: Buffer.from(salt),
            type: argon2Types[type] || nativeArgon2.argon2id,
            timeCost: time,
            memoryCost: mem,
            parallelism: parallelism,
            hashLength: hashLen,
            raw: true,
        });
        return { hash: new Uint8Array(hash) };
    }
};

global.window = global;
require('../client-js/dist/bundle.min.js');
const ProofOfWork = global.WebCryptoHash.ProofOfWork;

function b64Decode(str) {
    return Uint8Array.from(Buffer.from(str, 'base64'));
}
function b64Encode(bytes) {
    return Buffer.from(bytes).toString('base64');
}

async function fetchJson(url, options = {}) {
    const res = await fetch(url, options);
    const body = await res.text();
    let parsedBody;
    try { parsedBody = JSON.parse(body); } catch { parsedBody = body; }
    if (!res.ok) {
        const errMsg = (typeof parsedBody === 'object' && parsedBody !== null && parsedBody.error)
            ? parsedBody.error
            : `HTTP Error ${res.status}: ${body}`;
        const err = new Error(errMsg);
        err.status = res.status;
        err.body = parsedBody;
        throw err;
    }
    return parsedBody;
}

function assertError(e, expectedStatus, expectedMessage) {
    if (e.status !== expectedStatus || e.message !== expectedMessage) {
        throw new Error(`Expected HTTP ${expectedStatus} with error '${expectedMessage}', but got HTTP ${e.status} with error '${e.message}'`);
    }
}

async function waitForPort(port, maxWaitMs = 30000) {
    const start = Date.now();
    while (Date.now() - start < maxWaitMs) {
        try {
            await new Promise((resolve, reject) => {
                const socket = new net.Socket();
                socket.setTimeout(500);
                socket.on('connect', () => { socket.destroy(); resolve(); });
                socket.on('timeout', () => { socket.destroy(); reject(new Error('timeout')); });
                socket.on('error', (err) => { socket.destroy(); reject(err); });
                socket.connect(port, '127.0.0.1');
            });
            return true;
        } catch {
            await new Promise(r => setTimeout(r, 500));
        }
    }
    return false;
}

const pythonDir = path.resolve(__dirname, '../servers/python/example/fastapi/');
const venvDir = path.join(pythonDir, 'build_and_test_venv');
const isWin = process.platform === 'win32';
const pyBin = isWin ? path.join(venvDir, 'Scripts', 'python.exe') : path.join(venvDir, 'bin', 'python');

const servers = [
    {
        name: "Python FastAPI",
        setup: async () => {
            console.log("Setting up Python virtual environment...");
            const { execSync } = require('child_process');
            if (require('fs').existsSync(venvDir)) {
                require('fs').rmSync(venvDir, { recursive: true, force: true });
            }
            execSync(`python -m venv "${venvDir}"`);
            const pythonServerDir = path.resolve(__dirname, '../servers/python');
            execSync(`"${pyBin}" -m pip install --quiet -e "${pythonServerDir}[test]"`);
        },
        cmd: pyBin,
        args: ['-m', 'uvicorn', 'server:app', '--port', '8081'],
        cwd: pythonDir,
        env: {},
        port: 8081,
        bootTime: 5000,
        teardown: () => {
            console.log("Destroying Python virtual environment...");
            if (require('fs').existsSync(venvDir)) {
                require('fs').rmSync(venvDir, { recursive: true, force: true });
            }
        }
    },
    {
        name: "Rust Axum",
        cmd: 'cargo',
        args: ['run'],
        cwd: path.resolve(__dirname, '../servers/rust/example/axum_server/'),
        env: {},
        port: 8082,
        bootTime: 12000
    },
    {
        name: "JS Express",
        setup: async () => {
            const { execSync } = require('child_process');
            execSync('npm install', { cwd: path.resolve(__dirname, '../servers/js/example/express/') });
        },
        cmd: 'node',
        args: ['server.js'],
        cwd: path.resolve(__dirname, '../servers/js/example/express/'),
        env: {},
        port: 8083,
        bootTime: 4000
    }
];

async function testServer(serverConfig) {
    console.log(`\n========================================`);
    console.log(`Testing Server: ${serverConfig.name}`);
    console.log(`========================================`);

    const env = { ...process.env, POW_DEFAULT_DIFFICULTY: '4', ...serverConfig.env };

    return new Promise(async (resolve) => {
        try {
            if (serverConfig.setup) await serverConfig.setup();
        } catch (e) {
            console.error(`[${serverConfig.name} SETUP ERR] ${e.message}`);
            resolve(false);
            return;
        }

        const procOptions = { cwd: serverConfig.cwd, env };
        const serverProc = spawn(serverConfig.cmd, serverConfig.args, procOptions);

        let passed = false;

        try {
            console.log(`Waiting up to ${serverConfig.bootTime}ms for server on port ${serverConfig.port}...`);
            const isUp = await waitForPort(serverConfig.port, serverConfig.bootTime);
            if (!isUp) throw new Error("Server failed to open port in time.");

            const baseUrl = `http://127.0.0.1:${serverConfig.port}`;

            // ── Test 1: Valid Solution ────────────────────────────────────────
            console.log(`[1] Requesting challenge...`);
            const challengeData = await fetchJson(`${baseUrl}/challenge`);
            console.log(`    req_id: ${challengeData.req_id}, difficulty: ${challengeData.difficulty}`);

            console.log(`[2] Solving PoW...`);
            const challengeBytes = b64Decode(challengeData.challenge);
            const pow = new ProofOfWork();
            const startNonce = new Uint8Array(32);
            crypto.getRandomValues(startNonce);
            const t0 = Date.now();
            const validNonceBytes = await pow.minePOW(challengeBytes, startNonce, challengeData.difficulty);
            console.log(`    Solved in ${Date.now() - t0}ms`);
            const nonceStr = b64Encode(validNonceBytes);

            console.log(`[3] Submitting valid solution...`);
            const submitRes = await fetchJson(`${baseUrl}/verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    req_id: challengeData.req_id, challenge: challengeData.challenge,
                    difficulty: challengeData.difficulty, nonce: nonceStr, timestamp: new Date().toISOString()
                })
            });
            if (!submitRes.message?.includes('successfully')) throw new Error(`Unexpected response: ${JSON.stringify(submitRes)}`);
            console.log('    ' + ok('Valid solution accepted.'));

            // ── Test 2: Replay Attack ─────────────────────────────────────────
            console.log(`[4] Replay Attack...`);
            let replayRejected = false;
            try {
                await fetchJson(`${baseUrl}/verify`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        req_id: challengeData.req_id, challenge: challengeData.challenge,
                        difficulty: challengeData.difficulty, nonce: nonceStr, timestamp: new Date().toISOString()
                    })
                });
            } catch (e) { assertError(e, 400, "Challenge not found or expired"); replayRejected = true; console.log('    ' + ok('Replay rejected.')); }
            if (!replayRejected) throw new Error("Replay was NOT rejected!");

            // ── Test 3: Tampered Nonce ────────────────────────────────────────
            console.log(`[5] Tampered Nonce...`);
            let tamperedRejected = false;
            const ch2 = await fetchJson(`${baseUrl}/challenge`);
            const tamperedNonce = '!!' + nonceStr.substring(2) + '!!';
            try {
                await fetchJson(`${baseUrl}/verify`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        req_id: ch2.req_id, challenge: ch2.challenge,
                        difficulty: ch2.difficulty, nonce: tamperedNonce, timestamp: new Date().toISOString()
                    })
                });
            } catch (e) { assertError(e, 400, "Invalid Proof of Work"); tamperedRejected = true; console.log('    ' + ok('Tampered nonce rejected.')); }
            if (!tamperedRejected) throw new Error("Tampered nonce was NOT rejected!");

            // ── Test 4: Difficulty Mismatch ───────────────────────────────────
            console.log(`[6] Difficulty Mismatch...`);
            let diffRejected = false;
            const ch3 = await fetchJson(`${baseUrl}/challenge`);
            try {
                await fetchJson(`${baseUrl}/verify`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        req_id: ch3.req_id, challenge: ch3.challenge,
                        difficulty: 200, nonce: nonceStr, timestamp: new Date().toISOString()
                    })
                });
            } catch (e) { assertError(e, 400, "Difficulty mismatch"); diffRejected = true; console.log('    ' + ok('Difficulty mismatch rejected.')); }
            if (!diffRejected) throw new Error("Difficulty mismatch was NOT rejected!");

            // ── Test 5: Invalid req_id ────────────────────────────────────────
            console.log(`[7] Invalid req_id...`);
            let reqIdRejected = false;
            try {
                await fetchJson(`${baseUrl}/verify`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        req_id: "018e6924-b52a-71bc-bd61-bc8b3d88b49e", challenge: ch2.challenge,
                        difficulty: ch2.difficulty, nonce: nonceStr, timestamp: new Date().toISOString()
                    })
                });
            } catch (e) { assertError(e, 400, "Challenge not found or expired"); reqIdRejected = true; console.log('    ' + ok('Invalid req_id rejected.')); }
            if (!reqIdRejected) throw new Error("Invalid req_id was NOT rejected!");

            // ── Test 6: Tampered Challenge Salt ──────────────────────────────
            console.log(`[8] Tampered Challenge Salt...`);
            let saltRejected = false;
            const ch4 = await fetchJson(`${baseUrl}/challenge`);
            try {
                await fetchJson(`${baseUrl}/verify`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        req_id: ch4.req_id, challenge: challengeData.challenge, // Old salt
                        difficulty: ch4.difficulty, nonce: nonceStr, timestamp: new Date().toISOString()
                    })
                });
            } catch (e) { assertError(e, 400, "Invalid Proof of Work"); saltRejected = true; console.log('    ' + ok('Tampered challenge rejected.')); }
            if (!saltRejected) throw new Error("Tampered challenge was NOT rejected!");

            // ── Test 7: Malformed JSON ────────────────────────────────────────
            console.log(`[9] Malformed JSON...`);
            let malformedRejected = false;
            try {
                await fetchJson(`${baseUrl}/verify`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: `{"req_id": "${ch4.req_id}", "challenge": "${ch4.challenge}"` // missing closing brace & fields
                });
            } catch (e) { assertError(e, 400, "Invalid JSON"); malformedRejected = true; console.log('    ' + ok('Malformed JSON rejected.')); }
            if (!malformedRejected) throw new Error("Malformed JSON was NOT rejected!");

            // ── Test 8: Concurrency Race ──────────────────────────────────────
            console.log(`[10] Concurrency Race (10 simultaneous identical submissions)...`);
            const raceChallenge = await fetchJson(`${baseUrl}/challenge`);
            const raceNonce = new Uint8Array(32);
            crypto.getRandomValues(raceNonce);
            const raceNonceBytes = await pow.minePOW(b64Decode(raceChallenge.challenge), raceNonce, raceChallenge.difficulty);
            const raceNonceStr = b64Encode(raceNonceBytes);
            const racePayload = JSON.stringify({
                req_id: raceChallenge.req_id, challenge: raceChallenge.challenge,
                difficulty: raceChallenge.difficulty, nonce: raceNonceStr, timestamp: new Date().toISOString()
            });
            const raceResults = await Promise.all(
                Array.from({ length: 10 }, () =>
                    fetch(`${baseUrl}/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: racePayload })
                        .then(res => res.ok ? 1 : 0).catch(() => 0)
                )
            );
            const raceSuccess = raceResults.reduce((a, b) => a + b, 0);
            if (raceSuccess !== 1) throw new Error(`Concurrency attack FAILED! Accepted ${raceSuccess}/10 identical requests.`);
            console.log('    ' + ok('Concurrency: only 1/10 accepted.'));

            // ── Test 9: Oversized Nonce (DoS guard - SEC-3) ───────────────────
            console.log(`[11] Oversized Nonce (SEC-3 DoS guard)...`);
            let oversizedRejected = false;
            const ch5 = await fetchJson(`${baseUrl}/challenge`);
            const oversizedNonce = Buffer.alloc(200, 0x41).toString('base64'); // 200 bytes → way over 64
            try {
                await fetchJson(`${baseUrl}/verify`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        req_id: ch5.req_id, challenge: ch5.challenge,
                        difficulty: ch5.difficulty, nonce: oversizedNonce, timestamp: new Date().toISOString()
                    })
                });
            } catch (e) {
                if (e.status === 400) { oversizedRejected = true; console.log('    ' + ok('Oversized nonce rejected (HTTP 400).')); }
                else { throw e; }
            }
            if (!oversizedRejected) throw new Error("Oversized nonce was NOT rejected!");

            // Resolve the dangling ch5 so the IP slot is freed before test 12.
            {
                const ch5Nonce = new Uint8Array(32);
                crypto.getRandomValues(ch5Nonce);
                const ch5NonceBytes = await pow.minePOW(b64Decode(ch5.challenge), ch5Nonce, ch5.difficulty);
                await fetchJson(`${baseUrl}/verify`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        req_id: ch5.req_id, challenge: ch5.challenge,
                        difficulty: ch5.difficulty, nonce: b64Encode(ch5NonceBytes), timestamp: new Date().toISOString()
                    })
                });
            }

            // ── Test 10: ChallengeAlreadyActive ─────────────────────────────
            console.log(`[12] ChallengeAlreadyActive (same IP hits /challenge twice)...`);
            const dupChallenge1 = await fetchJson(`${baseUrl}/challenge`);
            let dupRejected = false;
            try {
                await fetchJson(`${baseUrl}/challenge`);
            } catch (e) {
                if (e.status === 429) { dupRejected = true; console.log('    ' + ok('Duplicate challenge request rejected (HTTP 429).')); }
                else { throw e; }
            }
            if (!dupRejected) throw new Error("ChallengeAlreadyActive was NOT enforced!");
            const dupNonce = new Uint8Array(32); crypto.getRandomValues(dupNonce);
            const dupNonceBytes = await pow.minePOW(b64Decode(dupChallenge1.challenge), dupNonce, dupChallenge1.difficulty);
            await fetchJson(`${baseUrl}/verify`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    req_id: dupChallenge1.req_id, challenge: dupChallenge1.challenge,
                    difficulty: dupChallenge1.difficulty, nonce: b64Encode(dupNonceBytes), timestamp: new Date().toISOString()
                })
            });

            passed = true;
            resolve(true);

        } catch (e) {
            console.error('    ' + fail(`ERROR testing ${serverConfig.name}: ${e.message}`));
            resolve(false);
        } finally {
            console.log(`Shutting down ${serverConfig.name}...`);
            if (process.platform === 'win32') {
                require('child_process').spawn("taskkill", ["/pid", serverProc.pid, '/f', '/t']);
            } else {
                serverProc.kill();
            }
            await new Promise(r => setTimeout(r, 1000));
            if (serverConfig.teardown) {
                try { serverConfig.teardown(); } catch (e) { console.error(`[${serverConfig.name} TEARDOWN ERR] ${e.message}`); }
            }
        }
    });
}

async function runAllTests() {
    console.log("Starting Unified End-to-End Tests...");
    let allPassed = true;
    for (const s of servers) {
        const res = await testServer(s);
        if (!res) allPassed = false;
    }
    console.log(`\n========================================`);
    if (allPassed) {
        console.log(ok('ALL SERVERS PASSED INTEGRATION TESTS'));
        process.exit(0);
    } else {
        console.log(fail('ONE OR MORE SERVERS FAILED'));
        process.exit(1);
    }
}

runAllTests();
