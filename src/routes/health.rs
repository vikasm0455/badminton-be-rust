use axum::extract::State;
use axum::response::IntoResponse;
use axum::{Json, http::StatusCode};
use serde_json::json;

use crate::state::AppState;

/// Liveness + dependency probe (used by Uptime Kuma / Watchtower).
pub async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    let db_ok = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.db)
        .await
        .is_ok();
    let redis_ok = match state.redis.clone() {
        Some(mut r) => {
            let pong: redis::RedisResult<String> = redis::cmd("PING").query_async(&mut r).await;
            pong.is_ok()
        }
        None => false,
    };

    let status = if db_ok { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (
        status,
        Json(json!({
            "status": if db_ok { "ok" } else { "degraded" },
            "service": "rallyup-api",
            "version": env!("CARGO_PKG_VERSION"),
            "db": db_ok,
            "redis": redis_ok,
        })),
    )
}
