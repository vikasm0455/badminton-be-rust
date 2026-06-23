use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::auth::{AdminUser, AuthUser};
use crate::error::ApiError;
use crate::models::ApiResponse;
use crate::state::{AppState, LiveEvent};
use crate::{notify, time};

#[derive(Serialize, sqlx::FromRow)]
pub struct ReservationView {
    pub id: Uuid,
    pub court_number: i16,
    pub credential_id: Option<Uuid>,
    pub credential_name: Option<String>,
    pub reserved_by: Uuid,
    pub reserved_by_name: String,
    pub court_type: String,
    pub player_count: Option<i16>,
    pub duration_minutes: i16,
    pub start_at: DateTime<Utc>,
    pub expiry_at: DateTime<Utc>,
    pub queue_number: Option<i16>,
    pub notes: Option<String>,
    pub status: String,
    pub completed_at: Option<DateTime<Utc>>,
    pub completed_by_name: Option<String>,
    pub created_at: DateTime<Utc>,
    #[sqlx(default)]
    pub duplicate_warning: bool,
}

pub async fn today(
    State(state): State<AppState>,
    _user: AuthUser,
) -> Result<Json<ApiResponse<Vec<ReservationView>>>, ApiError> {
    let mut rows: Vec<ReservationView> = sqlx::query_as(
        "SELECT r.id, r.court_number, r.credential_id, r.credential_name_snapshot AS credential_name,
                r.reserved_by, u.display_name AS reserved_by_name, r.court_type, r.player_count,
                r.duration_minutes, r.start_at, r.expiry_at, r.queue_number, r.notes, r.status,
                r.completed_at, cu.display_name AS completed_by_name, r.created_at
         FROM court_reservations r
         JOIN users u ON u.id = r.reserved_by
         LEFT JOIN users cu ON cu.id = r.completed_by
         WHERE r.game_date = $1
         ORDER BY (r.status = 'active') DESC, r.expiry_at ASC",
    )
    .bind(time::today())
    .fetch_all(&state.db)
    .await?;

    // Flag courts with more than one active, non-expired reservation (PRD §7.5).
    let now = time::now();
    let mut active_per_court: HashMap<i16, i32> = HashMap::new();
    for r in &rows {
        if r.status == "active" && r.expiry_at > now {
            *active_per_court.entry(r.court_number).or_insert(0) += 1;
        }
    }
    for r in &mut rows {
        if r.status == "active" && r.expiry_at > now {
            r.duplicate_warning = active_per_court.get(&r.court_number).copied().unwrap_or(0) > 1;
        }
    }
    Ok(Json(ApiResponse::ok(rows)))
}

#[derive(Deserialize)]
pub struct CreateReservationReq {
    pub court_number: i16,
    pub credential_id: Option<Uuid>,
    pub court_type: String,
    pub player_count: Option<i16>,
    pub duration_minutes: Option<i16>,
    /// "now" | "at_time"
    pub start_type: String,
    /// RFC3339 timestamp, required when start_type == "at_time".
    pub start_at: Option<String>,
    pub queue_number: Option<i16>,
    pub notes: Option<String>,
}

pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateReservationReq>,
) -> Result<Json<ApiResponse<ReservationView>>, ApiError> {
    if !(1..=53).contains(&req.court_number) {
        return Err(ApiError::BadRequest("Court number must be between 1 and 53.".into()));
    }
    if !matches!(req.court_type.as_str(), "full" | "half") {
        return Err(ApiError::BadRequest("court type must be full or half".into()));
    }
    let duration = req.duration_minutes.unwrap_or(45);
    if !(1..=45).contains(&duration) {
        return Err(ApiError::BadRequest("Duration must be between 1 and 45 minutes.".into()));
    }
    if let Some(pc) = req.player_count {
        if !(1..=8).contains(&pc) {
            return Err(ApiError::BadRequest("player count must be between 1 and 8".into()));
        }
    }
    if let Some(q) = req.queue_number {
        if !(1..=5).contains(&q) {
            return Err(ApiError::BadRequest("queue number must be between 1 and 5".into()));
        }
    }
    let notes = req.notes.as_deref().map(str::trim).filter(|n| !n.is_empty());
    if let Some(n) = notes {
        if n.chars().count() > 100 {
            return Err(ApiError::BadRequest("notes must be 100 characters or fewer".into()));
        }
    }

    let now = time::now();
    let start_at = match req.start_type.as_str() {
        "now" => now,
        "at_time" => {
            let raw = req
                .start_at
                .as_deref()
                .ok_or_else(|| ApiError::BadRequest("start time is required".into()))?;
            let parsed = DateTime::parse_from_rfc3339(raw)
                .map_err(|_| ApiError::BadRequest("invalid start time".into()))?
                .with_timezone(&Utc);
            if parsed <= now + Duration::minutes(1) {
                return Err(ApiError::BadRequest("Start time must be in the future.".into()));
            }
            if parsed > now + Duration::hours(3) {
                return Err(ApiError::BadRequest("Start time must be within the next 3 hours.".into()));
            }
            parsed
        }
        _ => return Err(ApiError::BadRequest("start type must be now or at_time".into())),
    };

    // Resolve + lock the credential, snapshotting its name (survives midnight).
    let mut credential_name: Option<String> = None;
    if let Some(cid) = req.credential_id {
        let cred: Option<(String, chrono::NaiveDate)> =
            sqlx::query_as("SELECT bintang_name, game_date FROM court_credentials WHERE id = $1")
                .bind(cid)
                .fetch_optional(&state.db)
                .await?;
        let (name, gdate) = cred.ok_or_else(|| ApiError::BadRequest("credential not found".into()))?;
        if gdate != time::today() {
            return Err(ApiError::BadRequest("that credential is not for today".into()));
        }
        let locked: Option<(i16,)> = sqlx::query_as(
            "SELECT court_number FROM court_reservations
             WHERE credential_id = $1 AND status = 'active' AND expiry_at > NOW() LIMIT 1",
        )
        .bind(cid)
        .fetch_optional(&state.db)
        .await?;
        if let Some((court,)) = locked {
            return Err(ApiError::Conflict(format!("That credential is in use — Court {court}.")));
        }
        credential_name = Some(name);
    }

    let expiry_at = start_at + Duration::minutes(duration as i64);
    let id: (Uuid,) = sqlx::query_as(
        "INSERT INTO court_reservations
            (court_number, credential_id, credential_name_snapshot, reserved_by, court_type,
             player_count, duration_minutes, start_at, expiry_at, queue_number, notes, game_date)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id",
    )
    .bind(req.court_number)
    .bind(req.credential_id)
    .bind(&credential_name)
    .bind(user.id)
    .bind(&req.court_type)
    .bind(req.player_count)
    .bind(duration)
    .bind(start_at)
    .bind(expiry_at)
    .bind(req.queue_number)
    .bind(notes)
    .bind(time::today())
    .fetch_one(&state.db)
    .await?;

    state.broadcast(LiveEvent::ReservationsChanged);

    let by_name: (String,) = sqlx::query_as("SELECT display_name FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&state.db)
        .await?;
    let future_time = if start_at > now + Duration::minutes(1) {
        Some(start_at.with_timezone(&time::APP_TZ).format("%-I:%M %p").to_string())
    } else {
        None
    };
    notify::reservation_logged(&state, user.id, &by_name.0, req.court_number, duration, future_time);

    let view = load_one(&state, id.0).await?.ok_or(ApiError::NotFound)?;
    Ok(Json(ApiResponse::ok(view)))
}

pub async fn complete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<ReservationView>>, ApiError> {
    let row: Option<(String, i16)> =
        sqlx::query_as("SELECT status, court_number FROM court_reservations WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
    let (status, court) = row.ok_or(ApiError::NotFound)?;
    if status != "active" {
        return Err(ApiError::Conflict("This reservation is no longer active.".into()));
    }
    sqlx::query(
        "UPDATE court_reservations SET status = 'completed', completed_at = NOW(), completed_by = $1
         WHERE id = $2 AND status = 'active'",
    )
    .bind(user.id)
    .bind(id)
    .execute(&state.db)
    .await?;
    state.broadcast(LiveEvent::ReservationsChanged);

    let by_name: (String,) = sqlx::query_as("SELECT display_name FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&state.db)
        .await?;
    notify::reservation_complete(&state, user.id, court, &by_name.0);

    let view = load_one(&state, id).await?.ok_or(ApiError::NotFound)?;
    Ok(Json(ApiResponse::ok(view)))
}

pub async fn cancel(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    let res = sqlx::query("UPDATE court_reservations SET status = 'cancelled' WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    state.broadcast(LiveEvent::ReservationsChanged);
    Ok(Json(ApiResponse::message("Reservation cancelled.")))
}

#[derive(Deserialize)]
pub struct EditReservationReq {
    pub duration_minutes: Option<i16>,
    /// RFC3339.
    pub start_at: Option<String>,
    pub notes: Option<String>,
}

pub async fn edit(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<Uuid>,
    Json(req): Json<EditReservationReq>,
) -> Result<Json<ApiResponse<ReservationView>>, ApiError> {
    if let Some(d) = req.duration_minutes {
        if !(1..=180).contains(&d) {
            return Err(ApiError::BadRequest("duration out of range".into()));
        }
        sqlx::query("UPDATE court_reservations SET duration_minutes = $1 WHERE id = $2")
            .bind(d)
            .bind(id)
            .execute(&state.db)
            .await?;
    }
    if let Some(raw) = &req.start_at {
        let parsed = DateTime::parse_from_rfc3339(raw)
            .map_err(|_| ApiError::BadRequest("invalid start time".into()))?
            .with_timezone(&Utc);
        sqlx::query("UPDATE court_reservations SET start_at = $1 WHERE id = $2")
            .bind(parsed)
            .bind(id)
            .execute(&state.db)
            .await?;
    }
    if let Some(notes) = &req.notes {
        sqlx::query("UPDATE court_reservations SET notes = $1 WHERE id = $2")
            .bind(notes.trim())
            .bind(id)
            .execute(&state.db)
            .await?;
    }
    // Keep expiry_at consistent if duration/start changed (make_interval is immutable).
    if req.duration_minutes.is_some() || req.start_at.is_some() {
        sqlx::query(
            "UPDATE court_reservations
             SET expiry_at = start_at + make_interval(mins => duration_minutes::int)
             WHERE id = $1",
        )
        .bind(id)
        .execute(&state.db)
        .await?;
    }
    state.broadcast(LiveEvent::ReservationsChanged);
    let view = load_one(&state, id).await?.ok_or(ApiError::NotFound)?;
    Ok(Json(ApiResponse::ok(view)))
}

/// Force-unlock a credential by detaching it from its active reservation(s).
pub async fn unlock_credential(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(cred_id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    sqlx::query(
        "UPDATE court_reservations SET credential_id = NULL
         WHERE credential_id = $1 AND status = 'active'",
    )
    .bind(cred_id)
    .execute(&state.db)
    .await?;
    state.broadcast(LiveEvent::CredentialsChanged);
    Ok(Json(ApiResponse::message("Credential unlocked.")))
}

async fn load_one(state: &AppState, id: Uuid) -> Result<Option<ReservationView>, ApiError> {
    let row: Option<ReservationView> = sqlx::query_as(
        "SELECT r.id, r.court_number, r.credential_id, r.credential_name_snapshot AS credential_name,
                r.reserved_by, u.display_name AS reserved_by_name, r.court_type, r.player_count,
                r.duration_minutes, r.start_at, r.expiry_at, r.queue_number, r.notes, r.status,
                r.completed_at, cu.display_name AS completed_by_name, r.created_at
         FROM court_reservations r
         JOIN users u ON u.id = r.reserved_by
         LEFT JOIN users cu ON cu.id = r.completed_by
         WHERE r.id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}
