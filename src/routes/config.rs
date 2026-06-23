//! Auto-poll configuration (PRD §5.1.2, stored in app_config). Readable by any
//! member (so Settings can show current state); only admins can change it.

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::auth::{AdminUser, AuthUser};
use crate::error::ApiError;
use crate::models::ApiResponse;
use crate::state::AppState;
use crate::time;

#[derive(Serialize)]
pub struct AutoPollConfig {
    pub enabled: bool,
    pub time: String,
    pub note: String,
    pub final_reminder_time: String,
}

async fn read(state: &AppState, key: &str, default: &str) -> String {
    sqlx::query_as::<_, (String,)>("SELECT value FROM app_config WHERE key = $1")
        .bind(key)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .map(|r| r.0)
        .unwrap_or_else(|| default.to_string())
}

async fn write(state: &AppState, key: &str, value: &str) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO app_config (key, value, updated_at) VALUES ($1, $2, NOW())
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
    )
    .bind(key)
    .bind(value)
    .execute(&state.db)
    .await?;
    Ok(())
}

pub async fn get_auto_poll(
    State(state): State<AppState>,
    _user: AuthUser,
) -> Result<Json<ApiResponse<AutoPollConfig>>, ApiError> {
    Ok(Json(ApiResponse::ok(AutoPollConfig {
        enabled: read(&state, "auto_poll_enabled", "true").await == "true",
        time: read(&state, "auto_poll_time", "10:00").await,
        note: read(&state, "auto_poll_note", "").await,
        final_reminder_time: read(&state, "auto_poll_final_reminder_time", "17:00").await,
    })))
}

#[derive(Deserialize)]
pub struct UpdateAutoPollReq {
    pub enabled: Option<bool>,
    pub time: Option<String>,
    pub note: Option<String>,
    pub final_reminder_time: Option<String>,
}

pub async fn set_auto_poll(
    State(state): State<AppState>,
    _admin: AdminUser,
    Json(req): Json<UpdateAutoPollReq>,
) -> Result<Json<ApiResponse<AutoPollConfig>>, ApiError> {
    if let Some(enabled) = req.enabled {
        write(&state, "auto_poll_enabled", if enabled { "true" } else { "false" }).await?;
    }
    if let Some(t) = &req.time {
        time::parse_hhmm(t).ok_or_else(|| ApiError::BadRequest("invalid time (HH:MM)".into()))?;
        write(&state, "auto_poll_time", t.trim()).await?;
    }
    if let Some(t) = &req.final_reminder_time {
        time::parse_hhmm(t).ok_or_else(|| ApiError::BadRequest("invalid time (HH:MM)".into()))?;
        write(&state, "auto_poll_final_reminder_time", t.trim()).await?;
    }
    if let Some(note) = &req.note {
        if note.chars().count() > 120 {
            return Err(ApiError::BadRequest("note too long".into()));
        }
        write(&state, "auto_poll_note", note.trim()).await?;
    }
    get_auto_poll(State(state), AuthUser { id: _admin.id }).await
}
