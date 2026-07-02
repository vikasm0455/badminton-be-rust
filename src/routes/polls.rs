use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, NaiveDate, NaiveTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::models::{ApiResponse, PublicUser};
use crate::routes::groups::active_group;
use crate::state::{AppState, LiveEvent};
use crate::{notify, time};

#[derive(Serialize)]
pub struct VoteEntry {
    pub user_id: Uuid,
    pub display_name: String,
    pub vote: String,
}

#[derive(Serialize)]
pub struct PollView {
    pub id: Uuid,
    pub game_date: NaiveDate,
    pub proposed_time: String,
    pub note: Option<String>,
    pub auto_created: bool,
    pub attendance_locked: bool,
    pub created_by: Uuid,
    pub created_by_name: String,
    pub created_at: DateTime<Utc>,
    pub yes_count: i64,
    pub no_count: i64,
    pub maybe_count: i64,
    pub votes: Vec<VoteEntry>,
    pub my_vote: Option<String>,
    pub attendees: Vec<PublicUser>,
}

#[derive(sqlx::FromRow)]
struct PollRow {
    id: Uuid,
    game_date: NaiveDate,
    proposed_time: NaiveTime,
    note: Option<String>,
    auto_created: bool,
    attendance_locked: bool,
    created_by: Uuid,
    created_by_name: String,
    created_at: DateTime<Utc>,
}

async fn load_poll_view(
    state: &AppState,
    poll_id: Uuid,
    viewer: Uuid,
    group_id: Uuid,
) -> Result<Option<PollView>, ApiError> {
    // Callers verify group membership, but filter here too so no future caller
    // can accidentally render another group's poll.
    let row: Option<PollRow> = sqlx::query_as(
        "SELECT p.id, p.game_date, p.proposed_time, p.note, p.auto_created,
                p.attendance_locked, p.created_by, u.display_name AS created_by_name, p.created_at
         FROM polls p JOIN users u ON u.id = p.created_by
         WHERE p.id = $1 AND p.group_id = $2",
    )
    .bind(poll_id)
    .bind(group_id)
    .fetch_optional(&state.db)
    .await?;
    let Some(p) = row else { return Ok(None) };

    let votes: Vec<VoteEntry> = sqlx::query_as::<_, (Uuid, String, String)>(
        "SELECT v.user_id, u.display_name, v.vote
         FROM poll_votes v JOIN users u ON u.id = v.user_id
         WHERE v.poll_id = $1
         ORDER BY v.voted_at ASC",
    )
    .bind(poll_id)
    .fetch_all(&state.db)
    .await?
    .into_iter()
    .map(|(user_id, display_name, vote)| VoteEntry { user_id, display_name, vote })
    .collect();

    let yes_count = votes.iter().filter(|v| v.vote == "yes").count() as i64;
    let no_count = votes.iter().filter(|v| v.vote == "no").count() as i64;
    let maybe_count = votes.iter().filter(|v| v.vote == "maybe").count() as i64;
    let my_vote = votes.iter().find(|v| v.user_id == viewer).map(|v| v.vote.clone());

    let attendees: Vec<PublicUser> = sqlx::query_as(
        "SELECT u.id, u.display_name FROM attendance a
         JOIN users u ON u.id = a.user_id WHERE a.poll_id = $1 ORDER BY u.display_name",
    )
    .bind(poll_id)
    .fetch_all(&state.db)
    .await?;

    Ok(Some(PollView {
        id: p.id,
        game_date: p.game_date,
        proposed_time: p.proposed_time.format("%H:%M").to_string(),
        note: p.note,
        auto_created: p.auto_created,
        attendance_locked: p.attendance_locked,
        created_by: p.created_by,
        created_by_name: p.created_by_name,
        created_at: p.created_at,
        yes_count,
        no_count,
        maybe_count,
        votes,
        my_vote,
        attendees,
    }))
}

pub async fn today(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<ApiResponse<Option<PollView>>>, ApiError> {
    let ctx = active_group(&state, user.id).await?;
    let id: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM polls WHERE game_date = $1 AND group_id = $2")
            .bind(time::today())
            .bind(ctx.group_id)
            .fetch_optional(&state.db)
            .await?;
    let view = match id {
        Some((pid,)) => load_poll_view(&state, pid, user.id, ctx.group_id).await?,
        None => None,
    };
    Ok(Json(ApiResponse::ok(view)))
}

/// The poll's group, verified against the caller's active group.
async fn poll_in_my_group(state: &AppState, poll_id: Uuid, user_id: Uuid) -> Result<Uuid, ApiError> {
    let ctx = active_group(state, user_id).await?;
    let group: Option<(Option<Uuid>,)> = sqlx::query_as("SELECT group_id FROM polls WHERE id = $1")
        .bind(poll_id)
        .fetch_optional(&state.db)
        .await?;
    let (group,) = group.ok_or(ApiError::NotFound)?;
    if group != Some(ctx.group_id) {
        return Err(ApiError::NotFound); // don't reveal other groups' polls
    }
    Ok(ctx.group_id)
}

pub async fn get_poll(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<PollView>>, ApiError> {
    let group_id = poll_in_my_group(&state, id, user.id).await?;
    let view = load_poll_view(&state, id, user.id, group_id).await?.ok_or(ApiError::NotFound)?;
    Ok(Json(ApiResponse::ok(view)))
}

#[derive(Deserialize)]
pub struct CreatePollReq {
    /// YYYY-MM-DD. Defaults to today.
    pub game_date: Option<String>,
    /// HH:MM.
    pub proposed_time: String,
    pub note: Option<String>,
}

pub async fn create_poll(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreatePollReq>,
) -> Result<Json<ApiResponse<PollView>>, ApiError> {
    let game_date = match &req.game_date {
        Some(s) => NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d")
            .map_err(|_| ApiError::BadRequest("invalid date".into()))?,
        None => time::today(),
    };
    let proposed_time = time::parse_hhmm(&req.proposed_time)
        .ok_or_else(|| ApiError::BadRequest("invalid time (use HH:MM)".into()))?;
    let note = req.note.as_deref().map(str::trim).filter(|n| !n.is_empty());
    if let Some(n) = note {
        if n.chars().count() > 120 {
            return Err(ApiError::BadRequest("note must be 120 characters or fewer".into()));
        }
    }

    let ctx = active_group(&state, user.id).await?;
    // Past dates: group admin only (PRD §5.4).
    if game_date < time::today() && !ctx.is_admin() {
        return Err(ApiError::BadRequest("Game date cannot be in the past.".into()));
    }

    let inserted: Result<(Uuid,), sqlx::Error> = sqlx::query_as(
        "INSERT INTO polls (created_by, game_date, proposed_time, note, group_id)
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(user.id)
    .bind(game_date)
    .bind(proposed_time)
    .bind(note)
    .bind(ctx.group_id)
    .fetch_one(&state.db)
    .await;

    let poll_id = match inserted {
        Ok((id,)) => id,
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => {
            return Err(ApiError::Conflict("A poll for today already exists.".into()));
        }
        Err(e) => return Err(ApiError::Db(e)),
    };

    let view = load_poll_view(&state, poll_id, user.id, ctx.group_id).await?.ok_or(ApiError::NotFound)?;
    state.broadcast(LiveEvent::PollChanged { poll_id });
    if game_date == time::today() {
        notify::poll_created(&state, ctx.group_id, Some(user.id), &view.created_by_name, &view.proposed_time, false);
    }
    Ok(Json(ApiResponse::ok(view)))
}

#[derive(Deserialize)]
pub struct VoteReq {
    pub vote: String,
}

pub async fn vote(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<VoteReq>,
) -> Result<Json<ApiResponse<PollView>>, ApiError> {
    let vote = req.vote.trim().to_lowercase();
    if !matches!(vote.as_str(), "yes" | "no" | "maybe") {
        return Err(ApiError::BadRequest("vote must be yes, no, or maybe".into()));
    }
    let group_id = poll_in_my_group(&state, id, user.id).await?;
    let locked: Option<(bool,)> =
        sqlx::query_as("SELECT attendance_locked FROM polls WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
    let (locked,) = locked.ok_or(ApiError::NotFound)?;
    if locked {
        return Err(ApiError::Conflict("Voting is closed — attendance is confirmed.".into()));
    }

    sqlx::query(
        "INSERT INTO poll_votes (poll_id, user_id, vote) VALUES ($1, $2, $3)
         ON CONFLICT (poll_id, user_id)
         DO UPDATE SET vote = EXCLUDED.vote, updated_at = NOW()",
    )
    .bind(id)
    .bind(user.id)
    .bind(&vote)
    .execute(&state.db)
    .await?;

    let view = load_poll_view(&state, id, user.id, group_id).await?.ok_or(ApiError::NotFound)?;
    state.broadcast(LiveEvent::PollChanged { poll_id: id });

    if vote == "yes" {
        let voter = view
            .votes
            .iter()
            .find(|v| v.user_id == user.id)
            .map(|v| v.display_name.clone())
            .unwrap_or_else(|| "Someone".into());
        notify::vote_yes(&state, group_id, id, &voter, view.yes_count);
    }
    Ok(Json(ApiResponse::ok(view)))
}

pub async fn retract_vote(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<PollView>>, ApiError> {
    let group_id = poll_in_my_group(&state, id, user.id).await?;
    let locked: Option<(bool,)> =
        sqlx::query_as("SELECT attendance_locked FROM polls WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
    let (locked,) = locked.ok_or(ApiError::NotFound)?;
    if locked {
        return Err(ApiError::Conflict("Voting is closed — attendance is confirmed.".into()));
    }
    sqlx::query("DELETE FROM poll_votes WHERE poll_id = $1 AND user_id = $2")
        .bind(id)
        .bind(user.id)
        .execute(&state.db)
        .await?;
    let view = load_poll_view(&state, id, user.id, group_id).await?.ok_or(ApiError::NotFound)?;
    state.broadcast(LiveEvent::PollChanged { poll_id: id });
    Ok(Json(ApiResponse::ok(view)))
}

#[derive(Deserialize)]
pub struct AttendanceReq {
    pub user_ids: Vec<Uuid>,
    /// Defaults true — confirming locks the poll. Admin may pass false to unlock.
    pub lock: Option<bool>,
}

pub async fn confirm_attendance(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<AttendanceReq>,
) -> Result<Json<ApiResponse<PollView>>, ApiError> {
    let group_id = poll_in_my_group(&state, id, user.id).await?;
    let ctx = active_group(&state, user.id).await?;
    let row: Option<(bool,)> = sqlx::query_as("SELECT attendance_locked FROM polls WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await?;
    let (locked,) = row.ok_or(ApiError::NotFound)?;
    if locked && !ctx.is_admin() {
        return Err(ApiError::Conflict(
            "Attendance is already confirmed. Ask an admin to unlock it.".into(),
        ));
    }

    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM attendance WHERE poll_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    for uid in &req.user_ids {
        // Only actual group members can be marked as attending.
        sqlx::query(
            "INSERT INTO attendance (poll_id, user_id, confirmed_by)
             SELECT $1, $2, $3
             WHERE EXISTS (SELECT 1 FROM group_members gm WHERE gm.group_id = $4 AND gm.user_id = $2)
             ON CONFLICT (poll_id, user_id) DO NOTHING",
        )
        .bind(id)
        .bind(uid)
        .bind(user.id)
        .bind(group_id)
        .execute(&mut *tx)
        .await?;
    }
    let lock = req.lock.unwrap_or(true);
    sqlx::query("UPDATE polls SET attendance_locked = $1 WHERE id = $2")
        .bind(lock)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    let view = load_poll_view(&state, id, user.id, group_id).await?.ok_or(ApiError::NotFound)?;
    Ok(Json(ApiResponse::ok(view)))
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct PollSummary {
    pub id: Uuid,
    pub game_date: NaiveDate,
    pub note: Option<String>,
    pub yes_count: i64,
    pub attendee_count: i64,
}

pub async fn history(
    State(state): State<AppState>,
    user: AuthUser,
    Query(q): Query<HistoryQuery>,
) -> Result<Json<ApiResponse<Vec<PollSummary>>>, ApiError> {
    let ctx = active_group(&state, user.id).await?;
    let limit = q.limit.unwrap_or(30).clamp(1, 100);
    let offset = q.offset.unwrap_or(0).max(0);
    let rows: Vec<PollSummary> = sqlx::query_as(
        "SELECT p.id, p.game_date, p.note,
            (SELECT COUNT(*) FROM poll_votes v WHERE v.poll_id = p.id AND v.vote = 'yes') AS yes_count,
            (SELECT COUNT(*) FROM attendance a WHERE a.poll_id = p.id) AS attendee_count
         FROM polls p
         WHERE p.group_id = $3
         ORDER BY p.game_date DESC
         LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .bind(ctx.group_id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(ApiResponse::ok(rows)))
}

/// Active-group roster — used by the attendance picker (members can add
/// players who showed up without voting). Returns id + display name only.
pub async fn members(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<ApiResponse<Vec<PublicUser>>>, ApiError> {
    let ctx = active_group(&state, user.id).await?;
    let rows: Vec<PublicUser> = sqlx::query_as(
        "SELECT u.id, u.display_name
         FROM group_members gm JOIN users u ON u.id = gm.user_id
         WHERE gm.group_id = $1 AND u.status = 'active'
         ORDER BY u.display_name",
    )
    .bind(ctx.group_id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(ApiResponse::ok(rows)))
}

/// Delete a poll — group admin of the poll's group.
pub async fn delete_poll(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    poll_in_my_group(&state, id, user.id).await?;
    let ctx = active_group(&state, user.id).await?;
    if !ctx.is_admin() {
        return Err(ApiError::Forbidden);
    }
    sqlx::query("DELETE FROM polls WHERE id = $1").bind(id).execute(&state.db).await?;
    state.broadcast(LiveEvent::PollChanged { poll_id: id });
    Ok(Json(ApiResponse::message("Poll deleted.")))
}
