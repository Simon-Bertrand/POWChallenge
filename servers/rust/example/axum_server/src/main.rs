use axum::{
    extract::{ConnectInfo, Extension},
    routing::{get, post},
    Router, Json,
};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use serde_json::{Value, json};
use tower_http::cors::CorsLayer;
use powchallenge_server::{
    POWCaptchaServer, CaptchaValidatedPOW, POWCaptchaError,
};
use std::env;

struct AppState {
    pow_server: POWCaptchaServer,
}

/// Map a domain error to the correct HTTP status code (SEC-4).
fn error_status(e: &POWCaptchaError) -> axum::http::StatusCode {
    if matches!(e, POWCaptchaError::ChallengeAlreadyActive) {
        return axum::http::StatusCode::TOO_MANY_REQUESTS; // 429
    }
    if matches!(e, POWCaptchaError::ServerBusy) {
        return axum::http::StatusCode::SERVICE_UNAVAILABLE; // 503
    }
    axum::http::StatusCode::BAD_REQUEST // 400
}

#[tokio::main]
async fn main() {
    let difficulty = env::var("POW_DEFAULT_DIFFICULTY")
        .unwrap_or_else(|_| "10".to_string())
        .parse::<u32>()
        .unwrap_or(10);

    let pow_server = POWCaptchaServer::new(difficulty, 300, false, None, 3600).await;
    let state = Arc::new(AppState { pow_server });

    let app = Router::new()
        .route("/challenge", get(get_challenge))
        .route("/verify", post(verify_pow))
        .layer(CorsLayer::permissive())
        .layer(Extension(state));

    let addr = SocketAddr::from(([127, 0, 0, 1], 8082));
    println!("Rust Axum Example listening on http://{}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}

async fn get_challenge(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<AppState>>,
) -> Result<Json<powchallenge_server::CaptchaResponse>, (axum::http::StatusCode, Json<Value>)> {
    let ip: IpAddr = peer.ip();
    match state.pow_server.get_challenge(ip, None).await {
        Ok(resp) => Ok(Json(resp)),
        Err(e) => Err((error_status(&e), Json(json!({"error": e.to_string()})))),
    }
}

async fn verify_pow(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<AppState>>,
    payload_res: Result<Json<CaptchaValidatedPOW>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let payload = match payload_res {
        Ok(Json(p)) => p,
        Err(_) => return Err((axum::http::StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid JSON"})))),
    };
    let ip: IpAddr = peer.ip();
    match state.pow_server.verify_pow(payload, ip, None).await {
        Ok(_) => Ok(Json(json!({"message": "Proof of Work validated successfully."}))),
        Err(e) => Err((error_status(&e), Json(json!({"error": e.to_string()})))),
    }
}
