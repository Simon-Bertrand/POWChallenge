# powchallenge_client

The companion client-side library for the POW Captcha ecosystem. It handles the computationally expensive Argon2id puzzle resolution seamlessly inside a Background Web Worker, ensuring your main browser UI thread maintains a smooth experience for legitimate users.

## Features
* **Zero-Interaction Security**: No need for users to click crosswalks or fire hydrants. Everything happens silently.
* **Web Worker Orchestration**: Automatically spawns and manages background threads to perform heavy cryptographic operations.
* **Pre-compiled WebAssembly**: Utilizes hyper-optimized WASM Argon2id bindings internally to maximize solving speed.

Install via bun:

```bash
bun add powchallenge_client
```

## How to Use

Integrating the client library is extremely simple. Fetch the challenge parameters from your backend, let the background worker mine the block, and submit the result back to your server.

```javascript
import { minePOWWithWorker } from 'powchallenge_client';

async function performSecureAction() {
    // 1. Fetch challenge parameters from your custom backend API
    const response = await fetch('/api/challenge');
    const challengeData = await response.json();
    
    // The challenge payload is base64 encoded by the server
    const challengeBase64 = challengeData.challenge;
    
    // 2. Mine the PoW in a non-blocking background thread
    // This will return the valid nonce in base64 format once the puzzle is solved
    const validNonceB64 = await minePOWWithWorker(challengeBase64, challengeData.difficulty);
    
    // 3. Submit the proof of work back to the server to securely complete the action
    const verifyResponse = await fetch('/api/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            req_id: challengeData.req_id,
            challenge: challengeData.challenge,
            nonce: validNonceB64,
            difficulty: challengeData.difficulty,
            timestamp: new Date().toISOString()
        })
    });
    
    if (verifyResponse.ok) {
        console.log("Action performed successfully!");
    } else {
        console.error("Proof of Work failed or expired.");
    }
}
```

For standard integrations, ensure your backend server utilizes the `powchallenge_server` package (available natively in Node.js, Python, and Rust).
