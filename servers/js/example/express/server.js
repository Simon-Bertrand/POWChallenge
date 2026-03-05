'use strict';

const express = require('express');
const cors = require('cors');
const { Address4, Address6 } = require('ip-address');
const lib = require('powchallenge_server');

const POWCaptchaServer = lib.POWCaptchaServer;
const ChallengeAlreadyActive = lib.ChallengeAlreadyActive;
const ServerBusy = lib.ServerBusy;
const POWCaptchaError = lib.POWCaptchaError;

const app = express();
app.use(cors());

// Limit request body to 64 KiB to prevent DoS via huge payloads
app.use(express.json({ limit: '64kb' }));

// Catch JSON parsing errors and return standardised 400 (SEC-4)
app.use((err, req, res, next) => {
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        return res.status(400).json({ error: 'Invalid JSON' });
    }
    next(err);
});

const difficulty = parseInt(process.env.POW_DEFAULT_DIFFICULTY || '10', 10);
const captchaServer = new POWCaptchaServer(difficulty, 300, false);

/**
 * Normalise the client IP:
 * - Unwrap IPv4-mapped IPv6 (::ffff:1.2.3.4 → 1.2.3.4) so subnet
 *   rate-limiting works correctly (SEC-5).
 * @param {import('express').Request} req
 * @returns {string}
 */
function getClientIp(req) {
    const raw = (req.headers['x-forwarded-for'] || req.ip || '127.0.0.1')
        .split(',')[0]
        .trim();
    const mapped = raw.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
    return mapped ? mapped[1] : raw;
}

/** Map domain errors to the appropriate HTTP status codes (SEC-4). */
function errorStatus(err) {
    if (err instanceof ChallengeAlreadyActive) return 429;
    if (err instanceof ServerBusy) return 503;
    if (err instanceof POWCaptchaError) return 400;
    return 500;
}

app.get('/challenge', async (req, res) => {
    try {
        const result = await captchaServer.get_challenge(getClientIp(req));
        res.json(result);
    } catch (e) {
        res.status(errorStatus(e)).json({ error: e.message });
    }
});

app.post('/verify', async (req, res) => {
    try {
        await captchaServer.verify_pow(req.body, getClientIp(req));
        res.json({ message: 'Proof of Work validated successfully.' });
    } catch (e) {
        res.status(errorStatus(e)).json({ error: e.message });
    }
});

const PORT = parseInt(process.env.PORT || '8083', 10);
app.listen(PORT, () => {
    console.log(`POW Captcha Example listening at http://localhost:${PORT}`);
});
