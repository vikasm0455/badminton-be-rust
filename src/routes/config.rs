//! Auto-poll configuration (PRD §5.1.2) — per GROUP. Readable by any member of
//! the active group (so Settings can show current state); only group admins can
//! change it.

use axum::Json;
use axum::extract::State;
use chrono::NaiveTime;
use serde::{Deserialize, Serialize};

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::models::ApiResponse;
use crate::routes::groups::{active_group, require_group_admin};
use crate::state::AppState;
use crate::time;

#[derive(Serialize)]
pub struct AutoPollConfig {
    pub enabled: bool,
    pub time: String,
    pub note: String,
    pub final_reminder_time: String,
}

pub async fn get_auto_poll(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<ApiResponse<AutoPollConfig>>, ApiError> {
    let ctx = active_group(&state, user.id).await?;
    let row: (bool, NaiveTime, String, NaiveTime) = sqlx::query_as(
        "SELECT auto_poll_enabled, auto_poll_time, auto_poll_note, final_reminder_time
         FROM groups WHERE id = $1",
    )
    .bind(ctx.group_id)
    .fetch_one(&state.db)
    .await?;
    Ok(Json(ApiResponse::ok(AutoPollConfig {
        enabled: row.0,
        time: row.1.format("%H:%M").to_string(),
        note: row.2,
        final_reminder_time: row.3.format("%H:%M").to_string(),
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
    user: AuthUser,
    Json(req): Json<UpdateAutoPollReq>,
) -> Result<Json<ApiResponse<AutoPollConfig>>, ApiError> {
    let ctx = require_group_admin(&state, user.id).await?;
    if let Some(enabled) = req.enabled {
        sqlx::query("UPDATE groups SET auto_poll_enabled = $1 WHERE id = $2")
            .bind(enabled)
            .bind(ctx.group_id)
            .execute(&state.db)
            .await?;
    }
    if let Some(t) = &req.time {
        let parsed = time::parse_hhmm(t).ok_or_else(|| ApiError::BadRequest("invalid time (HH:MM)".into()))?;
        sqlx::query("UPDATE groups SET auto_poll_time = $1 WHERE id = $2")
            .bind(parsed)
            .bind(ctx.group_id)
            .execute(&state.db)
            .await?;
    }
    if let Some(t) = &req.final_reminder_time {
        let parsed = time::parse_hhmm(t).ok_or_else(|| ApiError::BadRequest("invalid time (HH:MM)".into()))?;
        sqlx::query("UPDATE groups SET final_reminder_time = $1 WHERE id = $2")
            .bind(parsed)
            .bind(ctx.group_id)
            .execute(&state.db)
            .await?;
    }
    if let Some(note) = &req.note {
        if note.chars().count() > 120 {
            return Err(ApiError::BadRequest("note too long".into()));
        }
        sqlx::query("UPDATE groups SET auto_poll_note = $1 WHERE id = $2")
            .bind(note.trim())
            .bind(ctx.group_id)
            .execute(&state.db)
            .await?;
    }
    get_auto_poll(State(state), user).await
}
