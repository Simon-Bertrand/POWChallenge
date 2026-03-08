
use std::io::{self, BufRead};
use std::net::IpAddr;
use std::str::FromStr;
use serde::{Deserialize, Serialize};
use powchallenge_server::{POWCaptchaServer, CaptchaValidatedPOW};

#[derive(Deserialize)]
#[serde(tag = "action", content = "params")]
enum Command {
    #[serde(rename = "get_challenge")]
    GetChallenge {
        ip: String,
        fingerprint: Option<String>,
    },
    #[serde(rename = "validate_pow")]
    ValidatePow {
        request: CaptchaValidatedPOW,
        ip: String,
        fingerprint: Option<String>,
    },
    #[serde(rename = "set_max_active")]
    SetMaxActive {
        max: usize,
    },
    #[serde(rename = "generate_token")]
    GenerateToken {
        ip: String,
        user_agent: String,
        fingerprint: String,
    },
    #[serde(rename = "validate_token")]
    ValidateToken {
        token: String,
        ip: String,
        user_agent: String,
        fingerprint: String,
    },
}

#[derive(Serialize)]
#[serde(untagged)]
enum Response {
    Success { result: serde_json::Value },
    Error { error: String },
}

#[tokio::main]
async fn main() -> io::Result<()> {
    // Initialize server
    let mut server = POWCaptchaServer::new(10, 300, false, None, 3600).await;

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let cmd: Result<Command, _> = serde_json::from_str(&line);

        match cmd {
            Ok(Command::GetChallenge { ip, fingerprint }) => {
                let ip_addr = match IpAddr::from_str(&ip) {
                    Ok(addr) => addr,
                    Err(_) => {
                        println!("{}", serde_json::to_string(&Response::Error { error: "Invalid IP address".to_string() }).unwrap());
                        continue;
                    }
                };

                match server.get_challenge(ip_addr, fingerprint).await {
                    Ok(resp) => {
                        println!("{}", serde_json::to_string(&Response::Success { result: serde_json::to_value(resp).unwrap() }).unwrap());
                    }
                    Err(e) => {
                        println!("{}", serde_json::to_string(&Response::Error { error: e.to_string() }).unwrap());
                    }
                }
            }
            Ok(Command::ValidatePow { request, ip, fingerprint }) => {
                let ip_addr = match IpAddr::from_str(&ip) {
                    Ok(addr) => addr,
                    Err(_) => {
                        println!("{}", serde_json::to_string(&Response::Error { error: "Invalid IP address".to_string() }).unwrap());
                        continue;
                    }
                };

                match server.verify_pow(request, ip_addr, fingerprint).await {
                    Ok(valid) => {
                        println!("{}", serde_json::to_string(&Response::Success { result: serde_json::json!({ "valid": valid }) }).unwrap());
                    }
                    Err(e) => {
                        println!("{}", serde_json::to_string(&Response::Error { error: e.to_string() }).unwrap());
                    }
                }
            }
            Ok(Command::SetMaxActive { max }) => {
                server.set_max_active_challenges(max).await;
                println!("{}", serde_json::to_string(&Response::Success { result: serde_json::json!({ "ok": true }) }).unwrap());
            }
            Ok(Command::GenerateToken { ip, user_agent, fingerprint }) => {
                let ip_addr = IpAddr::from_str(&ip).unwrap_or("127.0.0.1".parse().unwrap());
                let token = server.generate_clearance_token(ip_addr, &user_agent, &fingerprint);
                println!("{}", serde_json::to_string(&Response::Success { result: serde_json::json!({ "token": token }) }).unwrap());
            }
            Ok(Command::ValidateToken { token, ip, user_agent, fingerprint }) => {
                let ip_addr = IpAddr::from_str(&ip).unwrap_or("127.0.0.1".parse().unwrap());
                let valid = server.validate_clearance_token(&token, ip_addr, &user_agent, &fingerprint);
                println!("{}", serde_json::to_string(&Response::Success { result: serde_json::json!({ "valid": valid }) }).unwrap());
            }
            Err(e) => {
                println!("{}", serde_json::to_string(&Response::Error { error: format!("Invalid JSON: {}", e) }).unwrap());
            }
        }
    }

    Ok(())
}
