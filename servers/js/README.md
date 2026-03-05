# powchallenge_server (Node.js)

A high-performance Proof-of-Work (PoW) CAPTCHA server library for the Node.js ecosystem. Protect your endpoints against botnets, DDoS attacks, and scraping by enforcing memory-hard Argon2id puzzles on the client side.

## Features
* **First-Class TypeScript**: Fully strongly-typed API for seamless IDE support.
* **Argon2id Memory-Hard Puzzles**: Defeats GPU and ASIC acceleration.
* **Pluggable Storage**: Uses in-memory mapping by default, scales horizontally with Redis for clusters or Kubernetes environments.
* **Zero-Interaction Security**: Verify challenges completely in the background without frustrating users.

## Installation

Install via npm, yarn, or pnpm:

```bash
npm install powchallenge_server
```

## How to Use

Here is a quick example of how to integrate the server library in an **Express** app:

```typescript
import express from 'express';
import { POWCaptchaServer } from 'powchallenge_server';

const app = express();
app.use(express.json());

// Initialize server: Base difficulty 10, expiry 5 minutes (300s), memory storage (false)
const captcha = new POWCaptchaServer(10, 300, false);

app.get('/challenge', async (req, res) => {
    try {
        const challenge = await captcha.get_challenge(req.ip);
        res.json(challenge);
    } catch (e: any) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/verify', async (req, res) => {
    try {
        await captcha.verify_pow(req.body, req.ip);
        res.json({ message: "Access Granted" });
    } catch (e: any) {
        res.status(400).json({ error: e.message || "Invalid Proof of Work" });
    }
});

app.listen(3000, () => console.log('Server running on port 3000'));
```
