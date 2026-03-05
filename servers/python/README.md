# powchallenge_server (Python)

A fully typed, robust Proof-of-Work (PoW) CAPTCHA server library for Python. This package provides the backend validation and challenge generation for the POW Captcha ecosystem. It prevents botnets, DDoS attacks, and credential stuffing by leveraging memory-hard cryptographic puzzles.

## Features
* **Argon2id Powered**: Defeats GPU and ASIC parallelism effectively.
* **Async IO Support**: Designed for high performance and fast concurrency.
* **Storage Backends**: Out-of-the-box support for internal Memory storage and Redis.
* **Framework Agnostic**: Integrates beautifully with FastAPI, Starlette, Flask, or raw ASGI/WSGI applications.

## Installation

Install using `pip`, `poetry`, or `uv`:

```bash
pip install powchallenge_server
```

## How to Use

Here is a simple example integrating with **FastAPI**:

```python
from fastapi import FastAPI, Request
from powchallenge_server import POWCaptchaServer
from powchallenge_server.interfaces import CaptchaValidatedPOW
from ipaddress import IPv4Address

app = FastAPI()

# Initialize server: Difficulty 10, 300 seconds validity, False for Memory Storage
captcha = POWCaptchaServer(10, 300, False)

@app.get("/challenge")
async def get_challenge(request: Request):
    ip = IPv4Address(request.client.host)
    challenge = await captcha.get_challenge(ip)
    return challenge

@app.post("/verify")
async def verify(payload: CaptchaValidatedPOW, request: Request):
    ip = IPv4Address(request.client.host)
    try:
        await captcha.verify_pow(payload, ip)
        return {"message": "Access Granted"}
    except Exception as e:
        return {"error": str(e)}
```

For advanced configuration, error handling, and Redis integration, please check the main documentation.
