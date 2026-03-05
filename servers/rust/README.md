# powchallenge_server (Rust)

A highly optimized, memory-safe, and high-performance Proof-of-Work (PoW) CAPTCHA server library for Rust. This crate provides the backend validation and challenge generation for the POW Captcha ecosystem, designed to protect your APIs from botnets and DDoS attacks while respecting user privacy.

## Features
* **Argon2id Memory-Hard Puzzles**: Defeats GPU and ASIC acceleration.
* **Dynamic Difficulty**: Scales dynamically based on threat levels.
* **Storage Support**: Includes in-memory and Redis storage backends.
* **Async-First**: Built for Tokio and fully compatible with Axum, Actix, and other async frameworks.

## Installation

Add the library to your `Cargo.toml`:

```toml
[dependencies]
powchallenge_server = "0.1.0"
```

## How to Use

Here is a basic example using `axum`:

```rust
use powchallenge_server::{POWCaptchaServer, CaptchaValidatedPOW};
use std::net::IpAddr;

#[tokio::main]
async fn main() {
    // Initialize server with base difficulty 10, valid for 300 seconds (5 minutes)
    // The boolean parameter determines if it should use a Redis backend (`true`) or Memory (`false`).
    let captcha = POWCaptchaServer::new(10, 300, false);
    
    // Generate a challenge for a user IP
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let challenge_response = captcha.get_challenge(ip, None).await.unwrap();
    
    // Verify a completed proof of work
    let payload = CaptchaValidatedPOW {
        req_id: challenge_response.req_id,
        challenge: challenge_response.challenge,
        nonce: "client_generated_nonce_b64".to_string(),
        difficulty: challenge_response.difficulty,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    
    match captcha.verify_pow(payload, ip).await {
        Ok(_) => println!("User verified successfully!"),
        Err(e) => println!("Validation failed: {:?}", e),
    }
}
```

For more documentation on storage backends, configuration, and security guarantees, refer to the [main POW Captcha repository](https://github.com/Simon-Bertrand/Simple-PoW-Captcha).
