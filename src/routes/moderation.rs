//! Guideline 1.2 (UGC): report objectionable content + block abusive members.
//! Reports hide the item for the reporter and email the operator; blocks hide
//! ALL of the blocked member's content from the blocker's lists instantly
//! (every list query filters on user_blocks) and also notify the operator.

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use serde::Serialize;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::models::ApiResponse;
use crate::state::AppState;

const REPORTABLE: [&str; 4] = ["credential", "poll", "reservation", "user"];

#[derive(Deserialize)]
pub struct ReportReq {
    pub content_type: String,
    pub content_id: Uuid,
    pub note: Option<String>,
}

pub async fn report(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<ReportReq>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    if !REPORTABLE.contains(&req.content_type.as_str()) {
        return Err(ApiError::BadRequest("unknown content type".into()));
    }
    sqlx::query(
        "INSERT INTO content_reports (reporter_id, content_type, content_id, note)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (reporter_id, content_type, content_id) DO NOTHING",
    )
    .bind(user.id)
    .bind(&req.content_type)
    .bind(req.content_id)
    .bind(req.note.as_deref().map(|n| n.chars().take(500).collect::<String>()))
    .execute(&state.db)
    .await?;

    let reporter: (String,) = sqlx::query_as("SELECT display_name FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&state.db)
        .await?;
    crate::email::send_moderation_alert(
        &state,
        "RallyUp moderation: content reported",
        &format!(
            "Reporter: {} ({})\nContent type: {}\nContent id: {}\nNote: {}\n\nReview within 24h per App Store guideline 1.2.",
            reporter.0,
            user.id,
            req.content_type,
            req.content_id,
            req.note.as_deref().unwrap_or("-"),
        ),
    )
    .await;

    Ok(Json(ApiResponse::ok_msg(
        (),
        "Reported — it's hidden for you and our team will review it.",
    )))
}

#[derive(Deserialize)]
pub struct BlockReq {
    pub user_id: Uuid,
}

pub async fn block(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<BlockReq>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    if req.user_id == user.id {
        return Err(ApiError::BadRequest("You can't block yourself.".into()));
    }
    let exists: Option<(String,)> = sqlx::query_as("SELECT display_name FROM users WHERE id = $1")
        .bind(req.user_id)
        .fetch_optional(&state.db)
        .await?;
    let Some((blocked_name,)) = exists else {
        return Err(ApiError::NotFound);
    };
    sqlx::query(
        "INSERT INTO user_blocks (blocker_id, blocked_id) VALUES ($1, $2)
         ON CONFLICT (blocker_id, blocked_id) DO NOTHING",
    )
    .bind(user.id)
    .bind(req.user_id)
    .execute(&state.db)
    .await?;

    let blocker: (String,) = sqlx::query_as("SELECT display_name FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&state.db)
        .await?;
    crate::email::send_moderation_alert(
        &state,
        "RallyUp moderation: member blocked",
        &format!(
            "Blocker: {} ({})\nBlocked: {} ({})\n\nAll of the blocked member's content is now hidden from the blocker. Review within 24h per App Store guideline 1.2.",
            blocker.0, user.id, blocked_name, req.user_id,
        ),
    )
    .await;

    Ok(Json(ApiResponse::ok_msg(
        (),
        "Blocked — their posts are hidden from your app.",
    )))
}

pub async fn unblock(
    State(state): State<AppState>,
    user: AuthUser,
    Path(blocked_id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    sqlx::query("DELETE FROM user_blocks WHERE blocker_id = $1 AND blocked_id = $2")
        .bind(user.id)
        .bind(blocked_id)
        .execute(&state.db)
        .await?;
    Ok(Json(ApiResponse::ok_msg((), "Unblocked.")))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct BlockedUser {
    pub id: Uuid,
    pub display_name: String,
}

pub async fn blocked_list(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<ApiResponse<Vec<BlockedUser>>>, ApiError> {
    let rows: Vec<BlockedUser> = sqlx::query_as(
        "SELECT u.id, u.display_name
         FROM user_blocks b JOIN users u ON u.id = b.blocked_id
         WHERE b.blocker_id = $1
         ORDER BY u.display_name",
    )
    .bind(user.id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(ApiResponse::ok(rows)))
}
