use axum::Json;
use axum::extract::State;
use serde::Deserialize;
use serde_json::json;

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::models::ApiResponse;
use crate::state::AppState;

/// Public: the Service Worker needs this to create a subscription.
pub async fn vapid_public_key(
    State(state): State<AppState>,
) -> Json<ApiResponse<serde_json::Value>> {
    Json(ApiResponse::ok(json!({ "publicKey": state.vapid.public_key_b64 })))
}

#[derive(Deserialize)]
pub struct SubscribeReq {
    pub endpoint: String,
    pub keys: SubscribeKeys,
    pub device_label: Option<String>,
}

#[derive(Deserialize)]
pub struct SubscribeKeys {
    pub p256dh: String,
    pub auth: String,
}

pub async fn subscribe(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<SubscribeReq>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    if req.endpoint.is_empty() || req.keys.p256dh.is_empty() || req.keys.auth.is_empty() {
        return Err(ApiError::BadRequest("incomplete subscription".into()));
    }
    let label = req.device_label.as_deref().map(|s| s.chars().take(100).collect::<String>());
    // Upsert by endpoint: re-subscribing the same device refreshes its keys and
    // reactivates it (PRD §8.5 — SW re-registers after data clears).
    sqlx::query(
        "INSERT INTO push_subscriptions (user_id, endpoint, p256dh, auth, device_label, active)
         VALUES ($1, $2, $3, $4, $5, true)
         ON CONFLICT (endpoint)
         DO UPDATE SET user_id = EXCLUDED.user_id, p256dh = EXCLUDED.p256dh,
                       auth = EXCLUDED.auth, device_label = EXCLUDED.device_label, active = true",
    )
    .bind(user.id)
    .bind(&req.endpoint)
    .bind(&req.keys.p256dh)
    .bind(&req.keys.auth)
    .bind(label)
    .execute(&state.db)
    .await?;
    Ok(Json(ApiResponse::message("Subscribed.")))
}

#[derive(Deserialize)]
pub struct UnsubscribeReq {
    pub endpoint: String,
}

pub async fn unsubscribe(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<UnsubscribeReq>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    sqlx::query("DELETE FROM push_subscriptions WHERE endpoint = $1 AND user_id = $2")
        .bind(&req.endpoint)
        .bind(user.id)
        .execute(&state.db)
        .await?;
    Ok(Json(ApiResponse::message("Unsubscribed.")))
}
