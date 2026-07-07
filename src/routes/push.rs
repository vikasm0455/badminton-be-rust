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

// ---- native device tokens (iOS APNs / Android FCM) ---------------------------

#[derive(Deserialize)]
pub struct RegisterDeviceReq {
    /// "apns" | "fcm"
    pub platform: String,
    pub token: String,
    pub device_label: Option<String>,
}

pub async fn register_device(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<RegisterDeviceReq>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    if !matches!(req.platform.as_str(), "apns" | "fcm") {
        return Err(ApiError::BadRequest("platform must be apns or fcm".into()));
    }
    let token = req.token.trim();
    if token.is_empty() || token.len() > 4096 {
        return Err(ApiError::BadRequest("invalid device token".into()));
    }
    let label = req.device_label.as_deref().map(|s| s.chars().take(100).collect::<String>());
    // Upsert by token: a reinstall (or user switch) re-claims the same token.
    sqlx::query(
        "INSERT INTO device_tokens (user_id, platform, token, device_label, active)
         VALUES ($1, $2, $3, $4, true)
         ON CONFLICT (token)
         DO UPDATE SET user_id = EXCLUDED.user_id, platform = EXCLUDED.platform,
                       device_label = EXCLUDED.device_label, active = true",
    )
    .bind(user.id)
    .bind(&req.platform)
    .bind(token)
    .bind(label)
    .execute(&state.db)
    .await?;
    Ok(Json(ApiResponse::message("Device registered.")))
}

#[derive(Deserialize)]
pub struct UnregisterDeviceReq {
    pub token: String,
}

pub async fn unregister_device(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<UnregisterDeviceReq>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    sqlx::query("DELETE FROM device_tokens WHERE token = $1 AND user_id = $2")
        .bind(req.token.trim())
        .bind(user.id)
        .execute(&state.db)
        .await?;
    Ok(Json(ApiResponse::message("Device unregistered.")))
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
