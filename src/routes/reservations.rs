use axum::Json;
use axum::extract::{Multipart, Path, State};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{AdminUser, AuthUser};
use crate::error::ApiError;
use crate::models::ApiResponse;
use crate::ocr::BoardCourt;
use crate::state::{AppState, LiveEvent};
use crate::{notify, ocr, time};

#[derive(Serialize, sqlx::FromRow)]
pub struct ReservationView {
    pub id: Uuid,
    pub court_number: i16,
    pub credential_id: Option<Uuid>,
    pub credential_name: Option<String>,
    /// Comma-joined names of every login attached to this reservation (a whole
    /// group on one court). Falls back to credential_name for legacy rows.
    #[sqlx(default)]
    pub attached_logins: Option<String>,
    /// IDs of every login attached to this reservation (for the edit form).
    #[sqlx(default)]
    pub attached_credential_ids: Vec<Uuid>,
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

/// A live reservation reduced to the fields that decide a court conflict.
struct ActiveSlot {
    court: i16,
    queue: Option<i16>,
    half: bool,
    start: DateTime<Utc>,
    expiry: DateTime<Utc>,
}

/// Two live reservations genuinely conflict (warrant a "duplicate" warning) only
/// when they fight for the SAME physical slot at the SAME time: same court, same
/// queue position (both NULL = the playing-now slot; a NULL never collides with a
/// numbered queue slot), overlapping time windows, and not two groups sharing
/// opposite halves of the court. Distinct queue positions (e.g. #3 and #4) and
/// back-to-back non-overlapping slots are legitimate and must NOT be flagged.
fn slots_conflict(a: &ActiveSlot, b: &ActiveSlot) -> bool {
    a.court == b.court
        && a.queue == b.queue
        && a.start < b.expiry
        && b.start < a.expiry
        && !(a.half && b.half)
}

pub async fn today(
    State(state): State<AppState>,
    _user: AuthUser,
) -> Result<Json<ApiResponse<Vec<ReservationView>>>, ApiError> {
    let mut rows: Vec<ReservationView> = sqlx::query_as(
        "SELECT r.id, r.court_number, r.credential_id, r.credential_name_snapshot AS credential_name,
                COALESCE(
                    (SELECT string_agg(rc.name_snapshot, ', ' ORDER BY rc.name_snapshot)
                     FROM reservation_credentials rc WHERE rc.reservation_id = r.id),
                    r.credential_name_snapshot
                ) AS attached_logins,
                COALESCE(
                    (SELECT array_agg(rc.credential_id) FROM reservation_credentials rc WHERE rc.reservation_id = r.id),
                    ARRAY[]::uuid[]
                ) AS attached_credential_ids,
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

    // Flag only genuine same-slot conflicts, not distinct queue positions or
    // half-court shares (PRD §7.5). Two members queued at #3 and #4 on one court
    // are expected, not a duplicate.
    let now = time::now();
    let active: Vec<(usize, ActiveSlot)> = rows
        .iter()
        .enumerate()
        .filter(|(_, r)| r.status == "active" && r.expiry_at > now)
        .map(|(i, r)| {
            (
                i,
                ActiveSlot {
                    court: r.court_number,
                    queue: r.queue_number,
                    half: r.court_type == "half",
                    start: r.start_at,
                    expiry: r.expiry_at,
                },
            )
        })
        .collect();
    for i in 0..active.len() {
        let me = &active[i].1;
        let dup = active.iter().enumerate().any(|(j, (_, other))| j != i && slots_conflict(me, other));
        let idx = active[i].0;
        rows[idx].duplicate_warning = dup;
    }
    Ok(Json(ApiResponse::ok(rows)))
}

#[derive(Deserialize)]
pub struct CreateReservationReq {
    pub court_number: i16,
    /// Single login (manual reservation form). Kept for back-compat.
    pub credential_id: Option<Uuid>,
    /// Multiple logins attached to one court (board scan). Takes precedence over
    /// credential_id when non-empty; all are locked to this reservation.
    #[serde(default)]
    pub credential_ids: Option<Vec<Uuid>>,
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

    // Resolve + lock every login to attach. The board scan sends several logins
    // for one court; the manual form sends one. Each must be today's and free.
    let cred_ids: Vec<Uuid> = match &req.credential_ids {
        Some(v) if !v.is_empty() => {
            let mut seen = std::collections::HashSet::new();
            v.iter().copied().filter(|id| seen.insert(*id)).collect()
        }
        _ => req.credential_id.into_iter().collect(),
    };

    let mut attached: Vec<(Uuid, String)> = Vec::new();
    for cid in &cred_ids {
        let cred: Option<(String, chrono::NaiveDate)> =
            sqlx::query_as("SELECT bintang_name, game_date FROM court_credentials WHERE id = $1")
                .bind(cid)
                .fetch_optional(&state.db)
                .await?;
        let (name, gdate) = cred.ok_or_else(|| ApiError::BadRequest("credential not found".into()))?;
        if gdate != time::today() {
            return Err(ApiError::BadRequest("that credential is not for today".into()));
        }
        // Locked if attached to any active reservation — legacy credential_id or
        // the join table (a login can only be on one court at a time).
        let locked: Option<(i16,)> = sqlx::query_as(
            "SELECT cr.court_number FROM court_reservations cr
             WHERE cr.status = 'active' AND cr.expiry_at > NOW()
               AND (cr.credential_id = $1
                    OR EXISTS (SELECT 1 FROM reservation_credentials rc
                               WHERE rc.reservation_id = cr.id AND rc.credential_id = $1))
             LIMIT 1",
        )
        .bind(cid)
        .fetch_optional(&state.db)
        .await?;
        if let Some((court,)) = locked {
            return Err(ApiError::Conflict(format!("{name}'s login is in use — Court {court}.")));
        }
        attached.push((*cid, name));
    }

    let primary_id = attached.first().map(|(id, _)| *id);
    let primary_name = attached.first().map(|(_, n)| n.clone());

    let expiry_at = start_at + Duration::minutes(duration as i64);
    let inserted = sqlx::query_as::<_, (Uuid,)>(
        "INSERT INTO court_reservations
            (court_number, credential_id, credential_name_snapshot, reserved_by, court_type,
             player_count, duration_minutes, start_at, expiry_at, queue_number, notes, game_date)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id",
    )
    .bind(req.court_number)
    .bind(primary_id)
    .bind(&primary_name)
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
    .await;
    let id: (Uuid,) = match inserted {
        Ok(v) => v,
        // Unique-index violation = a real duplicate for the same queue slot.
        Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23505") => {
            return Err(ApiError::Conflict(format!(
                "Court {} already has an active reservation for that queue slot.",
                req.court_number
            )));
        }
        Err(e) => return Err(e.into()),
    };

    // Attach every locked login to the new reservation (one court, many logins).
    for (cid, name) in &attached {
        sqlx::query(
            "INSERT INTO reservation_credentials (reservation_id, credential_id, name_snapshot)
             VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(id.0)
        .bind(cid)
        .bind(name)
        .execute(&state.db)
        .await?;
    }

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

// ---- board scan -------------------------------------------------------------

/// One COURT read from the status board with all of the group's posted logins
/// that matched onto it, as a single suggested reservation (one timer per court)
/// the user can confirm/edit before it's created.
#[derive(Serialize)]
pub struct BoardMatch {
    /// Every matched login on this court.
    pub credential_ids: Vec<Uuid>,
    pub bintang_names: Vec<String>,
    /// The subset of credential_ids already locked to another active reservation
    /// (they'll be skipped when this court is logged).
    pub already_in_use_ids: Vec<Uuid>,
    /// A court one of the matched logins is already on (for the UI hint).
    pub in_use_court: Option<i16>,
    pub court_number: i16,
    pub minutes_left: Option<i16>,
    /// "current" (playing now) | "queue" (waiting).
    pub location: String,
    pub queue_position: Option<i16>,
    pub current_players: Vec<String>,
    pub queue: Vec<String>,
    pub player_count: i16,
    pub court_type: String,
    /// Suggested timer plan, mirroring CreateReservationReq.
    pub start_type: String,
    /// Minutes from now until the court starts (0 when playing now).
    pub start_in_minutes: i16,
    pub duration_minutes: i16,
}

#[derive(Serialize)]
pub struct BoardScanResult {
    pub matches: Vec<BoardMatch>,
    pub detected_courts: usize,
    pub message: String,
}

/// Case-insensitive, token-based fuzzy match of a kiosk login name against the
/// (OCR-noisy) names read off the board. Tokens shorter than 3 chars are ignored
/// to avoid spurious hits. The user reviews every match, so we err toward recall.
fn name_matches(login: &str, board_names: &[String]) -> bool {
    let login_l = login.to_lowercase();
    let login_tokens: Vec<&str> = login_l
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 3)
        .collect();
    for bn in board_names {
        let bn_l = bn.to_lowercase();
        if bn_l == login_l {
            return true;
        }
        if login_tokens.iter().any(|t| bn_l.contains(t)) {
            return true;
        }
        if bn_l
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| t.len() >= 3)
            .any(|bt| login_l.contains(bt))
        {
            return true;
        }
    }
    false
}

/// OCR the facility status board, match today's posted logins onto it, and
/// return a reviewable list of suggested reservations (timers read off the
/// board). Creates nothing — the client confirms via the normal create route.
pub async fn scan_board(
    State(state): State<AppState>,
    _user: AuthUser,
    multipart: Multipart,
) -> Result<Json<ApiResponse<BoardScanResult>>, ApiError> {
    let max_bytes = state.config.max_upload_size_mb * 1024 * 1024;
    let (bytes, content_type) = crate::upload::read_image_field(multipart, max_bytes).await?;

    // Today's posted logins + the court each is currently locked to (if any).
    let creds: Vec<(Uuid, String, Option<i16>)> = sqlx::query_as(
        "SELECT c.id, c.bintang_name,
                (SELECT r.court_number FROM court_reservations r
                   WHERE (r.credential_id = c.id
                          OR EXISTS (SELECT 1 FROM reservation_credentials rc
                                     WHERE rc.reservation_id = r.id AND rc.credential_id = c.id))
                     AND r.status = 'active' AND r.expiry_at > NOW()
                   ORDER BY r.start_at DESC LIMIT 1) AS in_use_court
         FROM court_credentials c WHERE c.game_date = $1",
    )
    .bind(time::today())
    .fetch_all(&state.db)
    .await?;

    let board = ocr::extract_board(&state, &bytes, &content_type).await;
    let detected = board.len();

    let matches = build_matches(&creds, &board);

    let message = if detected == 0 {
        "Couldn't read the board clearly. Try a closer, straight-on photo — or log courts manually.".to_string()
    } else if matches.is_empty() {
        format!("Read {detected} court(s) but none matched a posted login. Post your court logins first, then rescan.")
    } else {
        format!("Matched {} of your login(s) across {detected} court(s) on the board.", matches.len())
    };

    Ok(Json(ApiResponse::ok(BoardScanResult { matches, detected_courts: detected, message })))
}

/// Group the matched logins by court: one suggested reservation per court (one
/// timer), with every login that landed on that court attached. A court is
/// "playing now" if any of its matched logins is in the current-players line,
/// otherwise it's queued at the earliest matched queue position.
fn build_matches(creds: &[(Uuid, String, Option<i16>)], board: &[BoardCourt]) -> Vec<BoardMatch> {
    // Resolve each login to its single best board panel (current beats queue).
    let resolved: Vec<Option<(usize, bool, Option<i16>)>> = creds
        .iter()
        .map(|(_, name, _)| {
            for (i, bc) in board.iter().enumerate() {
                if name_matches(name, &bc.current_players) {
                    return Some((i, true, None));
                }
            }
            for (i, bc) in board.iter().enumerate() {
                if let Some(p) = bc.queue.iter().position(|q| name_matches(name, std::slice::from_ref(q))) {
                    return Some((i, false, Some((p + 1) as i16)));
                }
            }
            None
        })
        .collect();

    // A doubles game seats at most 4; never suggest a larger "group".
    const MAX_PLAYERS: usize = 4;

    let mut out = Vec::new();
    for (bi, bc) in board.iter().enumerate() {
        // Every login that resolved to this court panel.
        let members: Vec<(usize, bool, Option<i16>)> = resolved
            .iter()
            .enumerate()
            .filter_map(|(ci, &r)| r.and_then(|(idx, cur, qp)| (idx == bi).then_some((ci, cur, qp))))
            .collect();
        if members.is_empty() {
            continue;
        }

        // Playing-now and queued logins are DIFFERENT groups (different people,
        // different time slots) — emit a separate reservation for each instead of
        // merging them into one oversized booking.
        for is_current in [true, false] {
            let group: Vec<(usize, Option<i16>)> = members
                .iter()
                .filter(|(_, cur, _)| *cur == is_current)
                .map(|(ci, _, qp)| (*ci, *qp))
                .collect();
            if group.is_empty() {
                continue;
            }

            let credential_ids: Vec<Uuid> = group.iter().map(|(ci, _)| creds[*ci].0).collect();
            let bintang_names: Vec<String> = group.iter().map(|(ci, _)| creds[*ci].1.clone()).collect();
            let already_in_use_ids: Vec<Uuid> = group
                .iter()
                .filter(|(ci, _)| creds[*ci].2.is_some())
                .map(|(ci, _)| creds[*ci].0)
                .collect();
            let in_use_court = group.iter().find_map(|(ci, _)| creds[*ci].2);
            let player_count = group.len().clamp(1, MAX_PLAYERS) as i16;

            let (location, queue_position, start_type, start_in_minutes, duration_minutes) = if is_current {
                // Playing now → runs out when the board's minutes-left hits 0.
                ("current", None, "now", 0i16, bc.minutes_left.map(|m| m.clamp(1, 45)).unwrap_or(45))
            } else {
                // Queued → starts when the current group frees the court, then a
                // standard 45-minute slot. Use the earliest matched queue position.
                let qpos = group.iter().filter_map(|(_, qp)| *qp).min().map(|p| p.clamp(1, 5));
                ("queue", qpos, "at_time", bc.minutes_left.map(|m| m.clamp(2, 170)).unwrap_or(15), 45)
            };

            out.push(BoardMatch {
                credential_ids,
                bintang_names,
                already_in_use_ids,
                in_use_court,
                court_number: bc.court_number,
                minutes_left: bc.minutes_left,
                location: location.to_string(),
                queue_position,
                current_players: bc.current_players.clone(),
                queue: bc.queue.clone(),
                player_count,
                court_type: "full".to_string(),
                start_type: start_type.to_string(),
                start_in_minutes,
                duration_minutes,
            });
        }
    }
    out
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

/// Three-state field: absent → None (leave as-is), present-null → Some(None)
/// (clear), present-value → Some(Some(v)). A plain Option<Option<T>> can't tell
/// absent from null, so we only run this when the key is present.
fn double_option<'de, D, T>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Some(Option::deserialize(de)?))
}

#[derive(Deserialize)]
pub struct EditReservationReq {
    pub court_number: Option<i16>,
    pub court_type: Option<String>,
    pub player_count: Option<i16>,
    pub duration_minutes: Option<i16>,
    /// RFC3339.
    pub start_at: Option<String>,
    /// Absent = leave as-is; null = clear; number = set (1–5).
    #[serde(default, deserialize_with = "double_option")]
    pub queue_number: Option<Option<i16>>,
    pub notes: Option<String>,
    /// Absent = leave logins as-is; otherwise set the attached logins to exactly
    /// this list (empty = detach all). Each must be free or already on this court.
    #[serde(default)]
    pub credential_ids: Option<Vec<Uuid>>,
}

/// Edit a logged court. Open to any member (like marking complete) so mistakes
/// can be fixed; each field is optional and only applied when present.
pub async fn edit(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<EditReservationReq>,
) -> Result<Json<ApiResponse<ReservationView>>, ApiError> {
    let dup = || ApiError::Conflict("That court and queue slot already has an active reservation.".into());

    if let Some(c) = req.court_number {
        if !(1..=53).contains(&c) {
            return Err(ApiError::BadRequest("Court number must be between 1 and 53.".into()));
        }
        match sqlx::query("UPDATE court_reservations SET court_number = $1 WHERE id = $2")
            .bind(c)
            .bind(id)
            .execute(&state.db)
            .await
        {
            Ok(_) => {}
            Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("23505") => return Err(dup()),
            Err(e) => return Err(e.into()),
        }
    }
    if let Some(t) = &req.court_type {
        if !matches!(t.as_str(), "full" | "half") {
            return Err(ApiError::BadRequest("court type must be full or half".into()));
        }
        sqlx::query("UPDATE court_reservations SET court_type = $1 WHERE id = $2")
            .bind(t)
            .bind(id)
            .execute(&state.db)
            .await?;
    }
    if let Some(p) = req.player_count {
        if !(1..=8).contains(&p) {
            return Err(ApiError::BadRequest("player count must be between 1 and 8".into()));
        }
        sqlx::query("UPDATE court_reservations SET player_count = $1 WHERE id = $2")
            .bind(p)
            .bind(id)
            .execute(&state.db)
            .await?;
    }
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
    if let Some(q) = req.queue_number {
        if let Some(qn) = q {
            if !(1..=5).contains(&qn) {
                return Err(ApiError::BadRequest("queue number must be between 1 and 5".into()));
            }
        }
        match sqlx::query("UPDATE court_reservations SET queue_number = $1 WHERE id = $2")
            .bind(q)
            .bind(id)
            .execute(&state.db)
            .await
        {
            Ok(_) => {}
            Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("23505") => return Err(dup()),
            Err(e) => return Err(e.into()),
        }
    }
    if let Some(notes) = &req.notes {
        let n = notes.trim();
        if n.chars().count() > 100 {
            return Err(ApiError::BadRequest("notes must be 100 characters or fewer".into()));
        }
        let val = if n.is_empty() { None } else { Some(n) };
        sqlx::query("UPDATE court_reservations SET notes = $1 WHERE id = $2")
            .bind(val)
            .bind(id)
            .execute(&state.db)
            .await?;
    }
    // Re-sync the attached logins to exactly the requested set. Each login must
    // be free or already on THIS court (lock check excludes this reservation).
    if let Some(raw) = &req.credential_ids {
        let mut new_ids: Vec<Uuid> = Vec::new();
        for cid in raw {
            if !new_ids.contains(cid) {
                new_ids.push(*cid);
            }
        }
        let mut resolved: Vec<(Uuid, String)> = Vec::new();
        for cid in &new_ids {
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
                "SELECT cr.court_number FROM court_reservations cr
                 WHERE cr.status = 'active' AND cr.expiry_at > NOW() AND cr.id <> $2
                   AND (cr.credential_id = $1
                        OR EXISTS (SELECT 1 FROM reservation_credentials rc
                                   WHERE rc.reservation_id = cr.id AND rc.credential_id = $1))
                 LIMIT 1",
            )
            .bind(cid)
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
            if let Some((court,)) = locked {
                return Err(ApiError::Conflict(format!("{name}'s login is in use — Court {court}.")));
            }
            resolved.push((*cid, name));
        }
        let mut tx = state.db.begin().await?;
        sqlx::query("DELETE FROM reservation_credentials WHERE reservation_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        for (cid, name) in &resolved {
            sqlx::query("INSERT INTO reservation_credentials (reservation_id, credential_id, name_snapshot) VALUES ($1, $2, $3)")
                .bind(id)
                .bind(cid)
                .bind(name)
                .execute(&mut *tx)
                .await?;
        }
        // Mirror the primary login onto the row for legacy/display fields.
        sqlx::query("UPDATE court_reservations SET credential_id = $1, credential_name_snapshot = $2 WHERE id = $3")
            .bind(resolved.first().map(|(c, _)| *c))
            .bind(resolved.first().map(|(_, n)| n.clone()))
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
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

/// Force-unlock a credential by detaching it from its active reservation(s) —
/// both as the primary login and as one of several attached via the board scan.
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
    // Also detach it where it was attached as a non-primary login on an active
    // reservation; otherwise the join-table lock would survive the unlock.
    sqlx::query(
        "DELETE FROM reservation_credentials rc
         USING court_reservations cr
         WHERE rc.credential_id = $1 AND rc.reservation_id = cr.id AND cr.status = 'active'",
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
                COALESCE(
                    (SELECT string_agg(rc.name_snapshot, ', ' ORDER BY rc.name_snapshot)
                     FROM reservation_credentials rc WHERE rc.reservation_id = r.id),
                    r.credential_name_snapshot
                ) AS attached_logins,
                COALESCE(
                    (SELECT array_agg(rc.credential_id) FROM reservation_credentials rc WHERE rc.reservation_id = r.id),
                    ARRAY[]::uuid[]
                ) AS attached_credential_ids,
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn slot(court: i16, queue: Option<i16>, half: bool, start_min: i64, dur_min: i64) -> ActiveSlot {
        let base = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let start = base + Duration::minutes(start_min);
        ActiveSlot { court, queue, half, start, expiry: start + Duration::minutes(dur_min) }
    }

    fn court(n: i16, mins: Option<i16>, current: &[&str], queue: &[&str]) -> BoardCourt {
        BoardCourt {
            court_number: n,
            minutes_left: mins,
            current_players: current.iter().map(|s| s.to_string()).collect(),
            queue: queue.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn cred(name: &str, in_use: Option<i16>) -> (Uuid, String, Option<i16>) {
        (Uuid::new_v4(), name.to_string(), in_use)
    }

    #[test]
    fn two_logins_on_one_court_make_one_match() {
        // The reported case: Suchi and Shalu both on Court 22 → one reservation.
        let creds = vec![cred("Suchi", None), cred("Shalu", None)];
        let board = vec![court(22, Some(20), &["Suchi", "Shalu", "Vikas", "Anu"], &[])];
        let m = build_matches(&creds, &board);
        assert_eq!(m.len(), 1, "should collapse to a single court reservation");
        assert_eq!(m[0].court_number, 22);
        assert_eq!(m[0].credential_ids.len(), 2);
        assert_eq!(m[0].bintang_names, vec!["Suchi".to_string(), "Shalu".to_string()]);
        assert_eq!(m[0].location, "current");
        assert_eq!(m[0].start_type, "now");
    }

    #[test]
    fn logins_on_different_courts_make_separate_matches() {
        let creds = vec![cred("Suchi", None), cred("Shalu", None)];
        let board = vec![
            court(22, Some(20), &["Suchi"], &[]),
            court(17, Some(10), &["Shalu"], &[]),
        ];
        let m = build_matches(&creds, &board);
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn queued_logins_use_earliest_position_and_one_timer() {
        // Suchi queue #3, Shalu queue #4 on one court → one queued reservation.
        let creds = vec![cred("Suchi", None), cred("Shalu", None)];
        let board = vec![court(22, Some(11), &["A", "B", "C", "D"], &["X", "Y", "Suchi", "Shalu"])];
        let m = build_matches(&creds, &board);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].location, "queue");
        assert_eq!(m[0].queue_position, Some(3)); // earliest of #3/#4
        assert_eq!(m[0].credential_ids.len(), 2);
    }

    #[test]
    fn current_and_queue_on_same_court_are_separate_reservations() {
        // Playing-now and queued are different groups → two reservations, not one.
        let creds = vec![cred("Suchi", None), cred("Shalu", None)];
        let board = vec![court(22, Some(15), &["Suchi"], &["Shalu"])];
        let m = build_matches(&creds, &board);
        assert_eq!(m.len(), 2);
        let cur = m.iter().find(|x| x.location == "current").unwrap();
        let q = m.iter().find(|x| x.location == "queue").unwrap();
        assert_eq!(cur.bintang_names, vec!["Suchi".to_string()]);
        assert_eq!(q.bintang_names, vec!["Shalu".to_string()]);
    }

    #[test]
    fn playing_now_and_queue_split_with_capped_player_count() {
        // The reported bug: Court 31 had 4 playing now + 2 queued, all group
        // logins — must NOT merge into one 6-player reservation.
        let creds = vec![
            cred("Hdd", None),
            cred("Jujub", None),
            cred("Sharan", None),
            cred("Vikam", None),
            cred("Suchi", None),
            cred("Shalu", None),
        ];
        let board = vec![court(31, Some(42), &["Hdd", "Jujub", "Sharan", "Vikam"], &["Suchi", "Shalu"])];
        let m = build_matches(&creds, &board);
        assert_eq!(m.len(), 2, "playing-now and queued must be separate reservations");
        let cur = m.iter().find(|x| x.location == "current").unwrap();
        let q = m.iter().find(|x| x.location == "queue").unwrap();
        assert_eq!(cur.player_count, 4);
        assert_eq!(cur.credential_ids.len(), 4);
        assert_eq!(q.player_count, 2);
        assert_eq!(q.queue_position, Some(1));
    }

    #[test]
    fn player_count_never_exceeds_four() {
        let creds = vec![
            cred("Aaa", None),
            cred("Bbb", None),
            cred("Ccc", None),
            cred("Ddd", None),
            cred("Eee", None),
        ];
        let board = vec![court(5, Some(20), &["Aaa", "Bbb", "Ccc", "Ddd", "Eee"], &[])];
        let m = build_matches(&creds, &board);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].player_count, 4);
    }

    #[test]
    fn already_in_use_login_is_flagged_not_dropped() {
        let creds = vec![cred("Suchi", Some(9)), cred("Shalu", None)];
        let board = vec![court(22, Some(20), &["Suchi", "Shalu"], &[])];
        let m = build_matches(&creds, &board);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].already_in_use_ids.len(), 1);
        assert_eq!(m[0].already_in_use_ids[0], creds[0].0);
        assert_eq!(m[0].in_use_court, Some(9));
    }

    #[test]
    fn unmatched_logins_produce_no_match() {
        let creds = vec![cred("Zzz", None)];
        let board = vec![court(22, Some(20), &["Suchi", "Shalu"], &[])];
        assert!(build_matches(&creds, &board).is_empty());
    }

    #[test]
    fn distinct_queue_positions_do_not_conflict() {
        // The reported bug: Suchi at queue #3 and Shalu at queue #4 on Court 22.
        assert!(!slots_conflict(&slot(22, Some(3), false, 0, 45), &slot(22, Some(4), false, 0, 45)));
    }

    #[test]
    fn two_playing_now_full_courts_conflict() {
        // Both claim the playing-now slot (queue NULL) on the same court, same time.
        assert!(slots_conflict(&slot(22, None, false, 0, 45), &slot(22, None, false, 0, 45)));
    }

    #[test]
    fn playing_now_and_queued_do_not_conflict() {
        // NULL (playing now) never collides with a numbered queue slot.
        assert!(!slots_conflict(&slot(22, None, false, 0, 45), &slot(22, Some(1), false, 0, 45)));
    }

    #[test]
    fn same_queue_slot_logged_twice_conflicts() {
        // A genuine accidental duplicate: same court, same queue position, overlapping.
        assert!(slots_conflict(&slot(9, Some(2), false, 5, 45), &slot(9, Some(2), false, 5, 45)));
    }

    #[test]
    fn two_half_court_shares_do_not_conflict() {
        // Two groups on opposite halves of the same court.
        assert!(!slots_conflict(&slot(17, None, true, 0, 45), &slot(17, None, true, 0, 45)));
    }

    #[test]
    fn back_to_back_non_overlapping_do_not_conflict() {
        // 0..45 then 45..90 on the same court — sequential, legitimate.
        assert!(!slots_conflict(&slot(5, None, false, 0, 45), &slot(5, None, false, 45, 45)));
    }

    #[test]
    fn different_courts_never_conflict() {
        assert!(!slots_conflict(&slot(1, None, false, 0, 45), &slot(2, None, false, 0, 45)));
    }
}
