//! Courts v1 domain logic: the per-court state machine (take / join / queue),
//! the kiosk board snapshot, and the expiry engine.
//!
//! Concurrency contract (see migrations/0009_clubs.sql): every mutation of a
//! court's state runs inside a transaction that first takes
//! `pg_advisory_xact_lock(hashtext(club_id || ':' || court_number))`, so a
//! court has exactly one writer at a time. Handlers and the engine both go
//! through this module; HTTP-only concerns (auth, envelopes, open-hours gate)
//! stay in routes/clubs.rs so these functions are testable against a bare pool.

use chrono::{DateTime, NaiveTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::state::AppState;
use crate::{metrics, time};

// ---- club row ---------------------------------------------------------------

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ClubRow {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub brand_color: String,
    pub court_count: i32,
    pub session_minutes: i32,
    pub queue_depth: i32,
    pub auto_extend: bool,
    pub opens_at: NaiveTime,
    pub closes_at: NaiveTime,
    pub kiosk_theme: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

pub const CLUB_COLUMNS: &str = "id, slug, name, brand_color, court_count, session_minutes, \
     queue_depth, auto_extend, opens_at, closes_at, kiosk_theme, status, created_at";

pub async fn club_by_slug(db: &PgPool, slug: &str) -> Result<Option<ClubRow>, sqlx::Error> {
    sqlx::query_as::<_, ClubRow>(&format!("SELECT {CLUB_COLUMNS} FROM clubs WHERE slug = $1"))
        .bind(slug)
        .fetch_optional(db)
        .await
}

impl ClubRow {
    /// Kiosk actions are allowed only within opening hours (server local time,
    /// same clock the rest of the app uses).
    pub fn open_now(&self) -> bool {
        let now = time::local_time_now();
        self.opens_at <= now && now < self.closes_at
    }
}

// ---- action inputs / errors -------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PlayerCred {
    pub username: String,
    pub password: String,
}

/// Per-credential validation failure, rendered into the kiosk modal inline.
#[derive(Debug, Serialize, PartialEq)]
pub struct CredError {
    pub username: String,
    /// 'not_found' | 'revoked' | 'bad_password' | 'on_court' | 'in_queue' | 'duplicate'
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub court_number: Option<i32>,
}

/// Why a kiosk action was refused.
#[derive(Debug)]
pub enum ActionError {
    /// Per-credential problems — success:false envelope with data.errors.
    Validation(Vec<CredError>),
    /// Court-level problem (closed / busy / wrong state) — human message.
    Court(String),
    Db(sqlx::Error),
}

impl From<sqlx::Error> for ActionError {
    fn from(e: sqlx::Error) -> Self {
        ActionError::Db(e)
    }
}

pub(crate) async fn lock_court(
    tx: &mut Transaction<'_, Postgres>,
    club_id: Uuid,
    court_number: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1 || ':' || $2))")
        .bind(club_id.to_string())
        .bind(court_number.to_string())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Take the per-credential advisory locks in sorted UUID order (sorted order
/// prevents deadlock between concurrent groups sharing players). The court
/// lock alone is NOT enough for the "at most one place per credential" rule —
/// the invariant spans the whole club, so two actions on *different* courts
/// must still serialize on any credential they share.
async fn lock_credentials(
    tx: &mut Transaction<'_, Postgres>,
    ids: &[Uuid],
) -> Result<(), sqlx::Error> {
    let mut sorted: Vec<Uuid> = ids.to_vec();
    sorted.sort();
    for id in sorted {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('cred:' || $1))")
            .bind(id.to_string())
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

/// Resolve every submitted {username, password} against the club's issued
/// credentials, collecting ALL failures so the kiosk can mark each field.
/// Resolution happens first; then every resolved credential is advisory-locked
/// (sorted order) BEFORE the on_court/in_queue membership checks, so the
/// double-use rule holds even across different courts' transactions.
async fn validate_players(
    tx: &mut Transaction<'_, Postgres>,
    club_id: Uuid,
    players: &[PlayerCred],
) -> Result<Vec<Uuid>, ActionError> {
    let mut errors: Vec<CredError> = Vec::new();
    let mut resolved: Vec<(String, Uuid)> = Vec::new();
    let mut seen: Vec<String> = Vec::new();

    // Phase 1: identity — existence, status, password.
    for p in players {
        let username = p.username.trim().to_string();
        let fail = |code: &'static str, court: Option<i32>| CredError {
            username: username.clone(),
            code,
            court_number: court,
        };
        if seen.iter().any(|s| s.eq_ignore_ascii_case(&username)) {
            errors.push(fail("duplicate", None));
            continue;
        }
        seen.push(username.clone());

        let row: Option<(Uuid, String, String)> = sqlx::query_as(
            "SELECT id, password, status FROM club_credentials
             WHERE club_id = $1 AND username = $2",
        )
        .bind(club_id)
        .bind(&username)
        .fetch_optional(&mut **tx)
        .await?;
        let Some((id, password, status)) = row else {
            errors.push(fail("not_found", None));
            continue;
        };
        if status == "revoked" {
            errors.push(fail("revoked", None));
            continue;
        }
        if password != p.password.trim() {
            errors.push(fail("bad_password", None));
            continue;
        }
        resolved.push((username, id));
    }

    // Phase 2: serialize on each resolved credential, THEN check placement.
    let resolved_ids: Vec<Uuid> = resolved.iter().map(|(_, id)| *id).collect();
    lock_credentials(tx, &resolved_ids).await?;

    let mut ids: Vec<Uuid> = Vec::new();
    for (username, id) in resolved {
        let fail = |code: &'static str, court: Option<i32>| CredError {
            username: username.clone(),
            code,
            court_number: court,
        };
        // Double-use: at most one active session OR one queue group.
        // in_queue is checked FIRST: the only unlocked-to-us transition is the
        // engine moving a credential queue->court, and promotion holds this
        // credential's advisory lock too — but ordering the checks against the
        // transition direction means even a promotion committing between the
        // two statements is still caught by the on_court check below.
        let in_queue: Option<(i32,)> = sqlx::query_as(
            "SELECT q.court_number FROM queue_players qp
             JOIN court_queues q ON q.id = qp.queue_id
             WHERE qp.credential_id = $1
             LIMIT 1",
        )
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?;
        if let Some((court,)) = in_queue {
            errors.push(fail("in_queue", Some(court)));
            continue;
        }
        let on_court: Option<(i32,)> = sqlx::query_as(
            "SELECT cs.court_number FROM session_players sp
             JOIN court_sessions cs ON cs.id = sp.session_id
             WHERE sp.credential_id = $1 AND cs.status = 'active'
             LIMIT 1",
        )
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?;
        if let Some((court,)) = on_court {
            errors.push(fail("on_court", Some(court)));
            continue;
        }
        ids.push(id);
    }

    if errors.is_empty() { Ok(ids) } else { Err(ActionError::Validation(errors)) }
}

/// The court row a mutation cares about: closed flag + active-session shape.
struct CourtState {
    closed: bool,
    session_id: Option<Uuid>,
    player_count: i64,
    ends_at: Option<DateTime<Utc>>,
}

impl CourtState {
    /// The active session's timer already hit zero but the engine hasn't
    /// resolved it yet — the court's next occupant is undecided.
    fn expired_unresolved(&self) -> bool {
        self.session_id.is_some() && self.ends_at.is_some_and(|e| e <= time::now())
    }
}

fn finishing_up(court_number: i32) -> ActionError {
    ActionError::Court(format!(
        "Court {court_number} is finishing up — check the board in a moment."
    ))
}

async fn court_state(
    tx: &mut Transaction<'_, Postgres>,
    club: &ClubRow,
    court_number: i32,
) -> Result<CourtState, ActionError> {
    let row: Option<(bool,)> =
        sqlx::query_as("SELECT closed FROM club_courts WHERE club_id = $1 AND number = $2")
            .bind(club.id)
            .bind(court_number)
            .fetch_optional(&mut **tx)
            .await?;
    let Some((closed,)) = row else {
        return Err(ActionError::Court(format!("Court {court_number} does not exist.")));
    };
    let session: Option<(Uuid, i64, DateTime<Utc>)> = sqlx::query_as(
        "SELECT cs.id, (SELECT COUNT(*) FROM session_players sp WHERE sp.session_id = cs.id),
                cs.ends_at
         FROM court_sessions cs
         WHERE cs.club_id = $1 AND cs.court_number = $2 AND cs.status = 'active'",
    )
    .bind(club.id)
    .bind(court_number)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(CourtState {
        closed,
        session_id: session.as_ref().map(|(id, _, _)| *id),
        player_count: session.as_ref().map(|(_, n, _)| *n).unwrap_or(0),
        ends_at: session.map(|(_, _, e)| e),
    })
}

fn check_group_size(n: usize, allowed: &[usize]) -> Result<(), ActionError> {
    if allowed.contains(&n) {
        return Ok(());
    }
    Err(ActionError::Court(match allowed {
        [2] => "Joining a half court takes exactly 2 players.".to_string(),
        _ => "Groups are exactly 2 or 4 players.".to_string(),
    }))
}

// ---- kiosk actions ----------------------------------------------------------

/// Take an available court with a group of exactly 2 or 4.
pub async fn take_court(
    db: &PgPool,
    club: &ClubRow,
    court_number: i32,
    players: &[PlayerCred],
) -> Result<(), ActionError> {
    check_group_size(players.len(), &[2, 4])?;
    let mut tx = db.begin().await?;
    lock_court(&mut tx, club.id, court_number).await?;

    let court = court_state(&mut tx, club, court_number).await?;
    if court.closed {
        return Err(ActionError::Court(format!("Court {court_number} is closed.")));
    }
    if court.expired_unresolved() {
        // Timer at zero but the engine hasn't decided the successor yet
        // (queue promotion vs extend vs clear) — don't let anyone jump it.
        return Err(finishing_up(court_number));
    }
    if court.session_id.is_some() {
        return Err(ActionError::Court(format!(
            "Court {court_number} is already in play — join the half court or queue instead."
        )));
    }

    let ids = validate_players(&mut tx, club.id, players).await?;
    let inserted: Result<Uuid, sqlx::Error> = sqlx::query_scalar(
        "INSERT INTO court_sessions (club_id, court_number, started_at, ends_at)
         VALUES ($1, $2, NOW(), NOW() + make_interval(mins => $3)) RETURNING id",
    )
    .bind(club.id)
    .bind(court_number)
    .bind(club.session_minutes)
    .fetch_one(&mut *tx)
    .await;
    let session_id: Uuid = match inserted {
        Ok(id) => id,
        // The partial unique index (one active session per court) is the
        // backstop for anything that slips the lock discipline: surface it as
        // a friendly conflict, not a 500.
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => {
            return Err(ActionError::Court(format!(
                "Court {court_number} was just taken — check the board."
            )));
        }
        Err(e) => return Err(e.into()),
    };
    for id in &ids {
        sqlx::query("INSERT INTO session_players (session_id, credential_id) VALUES ($1, $2)")
            .bind(session_id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Join the second half of a court that has an active 2-player session. The
/// running timer is untouched — the joiners share the remaining time.
pub async fn join_court(
    db: &PgPool,
    club: &ClubRow,
    court_number: i32,
    players: &[PlayerCred],
) -> Result<(), ActionError> {
    check_group_size(players.len(), &[2])?;
    let mut tx = db.begin().await?;
    lock_court(&mut tx, club.id, court_number).await?;

    let court = court_state(&mut tx, club, court_number).await?;
    if court.closed {
        return Err(ActionError::Court(format!("Court {court_number} is closed.")));
    }
    let Some(session_id) = court.session_id else {
        return Err(ActionError::Court(format!(
            "Court {court_number} is free — take it instead of joining."
        )));
    };
    if court.expired_unresolved() {
        // Joining a dead session would give the joiners zero seconds of play
        // before the engine clears or replaces it.
        return Err(finishing_up(court_number));
    }
    if court.player_count != 2 {
        return Err(ActionError::Court(format!(
            "Court {court_number} has no half game to join."
        )));
    }

    let ids = validate_players(&mut tx, club.id, players).await?;
    for id in &ids {
        sqlx::query("INSERT INTO session_players (session_id, credential_id) VALUES ($1, $2)")
            .bind(session_id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Queue a group of 2 or 4 behind a full court. Position is dense 1..N and
/// capped by the club's queue_depth.
pub async fn queue_court(
    db: &PgPool,
    club: &ClubRow,
    court_number: i32,
    players: &[PlayerCred],
) -> Result<i32, ActionError> {
    check_group_size(players.len(), &[2, 4])?;
    let mut tx = db.begin().await?;
    lock_court(&mut tx, club.id, court_number).await?;

    let court = court_state(&mut tx, club, court_number).await?;
    if court.closed {
        return Err(ActionError::Court(format!("Court {court_number} is closed.")));
    }
    if court.session_id.is_none() {
        return Err(ActionError::Court(format!(
            "Court {court_number} is free — take it instead of queueing."
        )));
    }
    if court.player_count < 4 {
        return Err(ActionError::Court(format!(
            "Court {court_number} still has open spots — join instead of queueing."
        )));
    }
    let (queue_len,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM court_queues WHERE club_id = $1 AND court_number = $2",
    )
    .bind(club.id)
    .bind(court_number)
    .fetch_one(&mut *tx)
    .await?;
    if queue_len >= club.queue_depth as i64 {
        return Err(ActionError::Court(format!(
            "Court {court_number}'s queue is full ({} groups).",
            club.queue_depth
        )));
    }

    let ids = validate_players(&mut tx, club.id, players).await?;
    let position: i32 = sqlx::query_scalar(
        "INSERT INTO court_queues (club_id, court_number, position)
         SELECT $1, $2, COALESCE(MAX(position), 0) + 1
         FROM court_queues WHERE club_id = $1 AND court_number = $2
         RETURNING position",
    )
    .bind(club.id)
    .bind(court_number)
    .fetch_one(&mut *tx)
    .await?;
    let queue_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM court_queues WHERE club_id = $1 AND court_number = $2 AND position = $3",
    )
    .bind(club.id)
    .bind(court_number)
    .bind(position)
    .fetch_one(&mut *tx)
    .await?;
    for id in &ids {
        sqlx::query("INSERT INTO queue_players (queue_id, credential_id) VALUES ($1, $2)")
            .bind(queue_id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(position)
}

// ---- expiry engine ----------------------------------------------------------

/// What one court's expiry resolved to (drives metrics + broadcast).
#[derive(Debug, PartialEq)]
pub enum EngineOutcome {
    /// Queue group promoted onto the court (after dropping `dropped` revoked groups).
    Promoted { dropped: usize },
    /// Same players keep the court, timer extended by session_minutes.
    Extended,
    /// Session ended, court now available (or closed).
    Cleared,
}

/// One engine pass: resolve every expired active session. Returns the club ids
/// whose boards changed so the caller can nudge their SSE streams. Safe to run
/// concurrently with kiosk traffic and other instances — each court is
/// resolved under its advisory lock with FOR UPDATE SKIP LOCKED.
pub async fn engine_tick(db: &PgPool) -> Result<Vec<Uuid>, sqlx::Error> {
    // Cheap unlocked scan for candidates; each is re-checked under its lock.
    let expired: Vec<(Uuid, i32)> = sqlx::query_as(
        "SELECT club_id, court_number FROM court_sessions
         WHERE status = 'active' AND ends_at <= NOW()",
    )
    .fetch_all(db)
    .await?;

    let mut changed: Vec<Uuid> = Vec::new();
    for (club_id, court_number) in expired {
        match expire_court(db, club_id, court_number).await? {
            Some(outcome) => {
                match &outcome {
                    EngineOutcome::Promoted { .. } => {
                        metrics::record_feature("kiosk_queue_promoted", "web");
                    }
                    EngineOutcome::Extended => {
                        metrics::record_feature("kiosk_session_auto_extended", "web");
                    }
                    EngineOutcome::Cleared => {}
                }
                if !changed.contains(&club_id) {
                    changed.push(club_id);
                }
            }
            None => {} // raced: someone else already resolved it
        }
    }
    Ok(changed)
}

/// Resolve one expired session under the court's advisory lock. Timer zero →
/// promote queue #1 (dropping revoked groups), else auto-extend, else clear.
pub async fn expire_court(
    db: &PgPool,
    club_id: Uuid,
    court_number: i32,
) -> Result<Option<EngineOutcome>, sqlx::Error> {
    let mut tx = db.begin().await?;
    lock_court(&mut tx, club_id, court_number).await?;

    // Re-check under the lock; SKIP LOCKED keeps two engine instances from
    // fighting over the same row.
    let session: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM court_sessions
         WHERE club_id = $1 AND court_number = $2 AND status = 'active' AND ends_at <= NOW()
         FOR UPDATE SKIP LOCKED",
    )
    .bind(club_id)
    .bind(court_number)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((session_id,)) = session else {
        return Ok(None);
    };

    let (session_minutes, auto_extend): (i32, bool) =
        sqlx::query_as("SELECT session_minutes, auto_extend FROM clubs WHERE id = $1")
            .bind(club_id)
            .fetch_one(&mut *tx)
            .await?;
    let closed: bool = sqlx::query_scalar(
        "SELECT closed FROM club_courts WHERE club_id = $1 AND number = $2",
    )
    .bind(club_id)
    .bind(court_number)
    .fetch_optional(&mut *tx)
    .await?
    // Missing court row (e.g. removed while a session raced onto it): treat
    // as closed so the orphan session drains instead of auto-extending forever.
    .unwrap_or(true);

    // Walk the queue front-to-back: promote the first fully-active group,
    // dropping any group containing a revoked credential.
    let mut dropped = 0usize;
    let promoted = loop {
        let head: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM court_queues
             WHERE club_id = $1 AND court_number = $2
             ORDER BY position LIMIT 1",
        )
        .bind(club_id)
        .bind(court_number)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((queue_id,)) = head else { break None };

        let (revoked_members,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM queue_players qp
             JOIN club_credentials c ON c.id = qp.credential_id
             WHERE qp.queue_id = $1 AND c.status <> 'active'",
        )
        .bind(queue_id)
        .fetch_one(&mut *tx)
        .await?;
        if revoked_members > 0 {
            // Drop the whole group and keep looking.
            remove_queue_group(&mut tx, club_id, court_number, queue_id).await?;
            dropped += 1;
            continue;
        }
        break Some(queue_id);
    };

    match promoted {
        // A closed court takes no new groups — its queue was already released
        // on closure, and any stragglers must not land on it.
        Some(queue_id) if !closed => {
            // Serialize the queue->court move against any kiosk action holding
            // these credentials' locks (same court -> sorted-creds order as
            // validate_players, so the global lock order stays acyclic).
            // Without this, a queued player taking a DIFFERENT free court at
            // the promotion instant could land in two sessions at once.
            let group_ids: Vec<Uuid> = sqlx::query_scalar(
                "SELECT credential_id FROM queue_players WHERE queue_id = $1",
            )
            .bind(queue_id)
            .fetch_all(&mut *tx)
            .await?;
            lock_credentials(&mut tx, &group_ids).await?;
            sqlx::query("UPDATE court_sessions SET status = 'done' WHERE id = $1")
                .bind(session_id)
                .execute(&mut *tx)
                .await?;
            let inserted: Result<Uuid, sqlx::Error> = sqlx::query_scalar(
                "INSERT INTO court_sessions (club_id, court_number, started_at, ends_at)
                 VALUES ($1, $2, NOW(), NOW() + make_interval(mins => $3)) RETURNING id",
            )
            .bind(club_id)
            .bind(court_number)
            .bind(session_minutes)
            .fetch_one(&mut *tx)
            .await;
            let new_session: Uuid = match inserted {
                Ok(id) => id,
                // Another writer beat us onto the court despite the expiry —
                // skip gracefully; the next tick re-evaluates this court.
                Err(sqlx::Error::Database(db)) if db.is_unique_violation() => {
                    return Ok(None);
                }
                Err(e) => return Err(e),
            };
            sqlx::query(
                "INSERT INTO session_players (session_id, credential_id)
                 SELECT $1, credential_id FROM queue_players WHERE queue_id = $2",
            )
            .bind(new_session)
            .bind(queue_id)
            .execute(&mut *tx)
            .await?;
            remove_queue_group(&mut tx, club_id, court_number, queue_id).await?;
            tx.commit().await?;
            Ok(Some(EngineOutcome::Promoted { dropped }))
        }
        // Queue empty (or court closed): auto-extend or clear.
        _ => {
            // A group containing a revoked credential never auto-extends —
            // revocation must eventually get them off the court.
            let (revoked_on_court,): (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM session_players sp
                 JOIN club_credentials c ON c.id = sp.credential_id
                 WHERE sp.session_id = $1 AND c.status <> 'active'",
            )
            .bind(session_id)
            .fetch_one(&mut *tx)
            .await?;
            if auto_extend && !closed && promoted.is_none() && revoked_on_court == 0 {
                sqlx::query(
                    "UPDATE court_sessions
                     SET ends_at = ends_at + make_interval(mins => $2), extensions = extensions + 1
                     WHERE id = $1",
                )
                .bind(session_id)
                .bind(session_minutes)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(Some(EngineOutcome::Extended))
            } else {
                sqlx::query("UPDATE court_sessions SET status = 'done' WHERE id = $1")
                    .bind(session_id)
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
                Ok(Some(EngineOutcome::Cleared))
            }
        }
    }
}

/// Delete one queue group and renumber the rest to a dense 1..N. The negative
/// two-step sidesteps the (club, court, position) unique index mid-shift.
async fn remove_queue_group(
    tx: &mut Transaction<'_, Postgres>,
    club_id: Uuid,
    court_number: i32,
    queue_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM court_queues WHERE id = $1")
        .bind(queue_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "UPDATE court_queues SET position = -position WHERE club_id = $1 AND court_number = $2",
    )
    .bind(club_id)
    .bind(court_number)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "WITH ranked AS (
             SELECT id, ROW_NUMBER() OVER (ORDER BY position DESC) AS new_pos
             FROM court_queues WHERE club_id = $1 AND court_number = $2 AND position < 0
         )
         UPDATE court_queues q SET position = ranked.new_pos
         FROM ranked WHERE q.id = ranked.id",
    )
    .bind(club_id)
    .bind(court_number)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Change a club's court count inside the caller's transaction. Shrinking
/// advisory-locks every to-be-removed court number (ascending, to avoid
/// deadlocks) and re-checks for active sessions UNDER those locks, so a
/// concurrent take/join on a removed court can never orphan a session. The
/// clubs row is locked FOR UPDATE so two concurrent resizes serialize on the
/// real current count, not a stale snapshot.
pub async fn resize_courts(
    tx: &mut Transaction<'_, Postgres>,
    club_id: Uuid,
    new_count: i32,
) -> Result<(), ActionError> {
    let (old_count,): (i32,) =
        sqlx::query_as("SELECT court_count FROM clubs WHERE id = $1 FOR UPDATE")
            .bind(club_id)
            .fetch_one(&mut **tx)
            .await?;

    if new_count < old_count {
        for number in (new_count + 1)..=old_count {
            lock_court(tx, club_id, number).await?;
        }
        // Re-check under the locks: nothing may be playing on a removed court.
        let (active,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM court_sessions
             WHERE club_id = $1 AND court_number > $2 AND status = 'active'",
        )
        .bind(club_id)
        .bind(new_count)
        .fetch_one(&mut **tx)
        .await?;
        if active > 0 {
            return Err(ActionError::Court(format!(
                "Courts above {new_count} still have games in play — wait for them to finish."
            )));
        }
        sqlx::query("DELETE FROM court_queues WHERE club_id = $1 AND court_number > $2")
            .bind(club_id)
            .bind(new_count)
            .execute(&mut **tx)
            .await?;
        sqlx::query("DELETE FROM club_courts WHERE club_id = $1 AND number > $2")
            .bind(club_id)
            .bind(new_count)
            .execute(&mut **tx)
            .await?;
    }

    sqlx::query("UPDATE clubs SET court_count = $1 WHERE id = $2")
        .bind(new_count)
        .bind(club_id)
        .execute(&mut **tx)
        .await?;
    // Grow: insert any missing rows.
    sqlx::query(
        "INSERT INTO club_courts (club_id, number)
         SELECT $1, s FROM generate_series(1, $2) s
         ON CONFLICT (club_id, number) DO NOTHING",
    )
    .bind(club_id)
    .bind(new_count)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// 3-second expiry loop, spawned from main (NOT build_app, so tests don't run
/// it). Keeps promoting after closing time — the board must resolve itself.
pub fn spawn_engine(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3));
        loop {
            interval.tick().await;
            match engine_tick(&state.db).await {
                Ok(changed) => {
                    for club_id in changed {
                        state.notify_club(club_id);
                    }
                }
                Err(e) => tracing::warn!(error = %e, "courts engine tick failed"),
            }
        }
    });
}

// ---- board snapshot ---------------------------------------------------------

fn group_label(usernames: &[String]) -> String {
    match usernames {
        [] => String::new(),
        [first] => first.clone(),
        [first, _] => format!("{first} pair"),
        [first, rest @ ..] => format!("{first} + {} others", rest.len()),
    }
}

/// The full kiosk board as JSON — served by GET /board and pushed verbatim on
/// the SSE stream, so the two can never disagree.
pub async fn board_snapshot(db: &PgPool, club: &ClubRow) -> Result<Value, sqlx::Error> {
    let now = time::now();

    let courts: Vec<(i32, bool, Option<String>)> = sqlx::query_as(
        "SELECT number, closed, closed_reason FROM club_courts
         WHERE club_id = $1 ORDER BY number",
    )
    .bind(club.id)
    .fetch_all(db)
    .await?;

    // Active sessions with players (deterministic order: issue time).
    let sessions: Vec<(i32, DateTime<Utc>, String)> = sqlx::query_as(
        "SELECT cs.court_number, cs.ends_at, c.username
         FROM court_sessions cs
         JOIN session_players sp ON sp.session_id = cs.id
         JOIN club_credentials c ON c.id = sp.credential_id
         WHERE cs.club_id = $1 AND cs.status = 'active'
         ORDER BY cs.court_number, c.issued_at, c.username",
    )
    .bind(club.id)
    .fetch_all(db)
    .await?;

    let queues: Vec<(i32, i32, String)> = sqlx::query_as(
        "SELECT q.court_number, q.position, c.username
         FROM court_queues q
         JOIN queue_players qp ON qp.queue_id = q.id
         JOIN club_credentials c ON c.id = qp.credential_id
         WHERE q.club_id = $1
         ORDER BY q.court_number, q.position, c.issued_at, c.username",
    )
    .bind(club.id)
    .fetch_all(db)
    .await?;

    let mut court_views: Vec<Value> = Vec::with_capacity(courts.len());
    for (number, closed, closed_reason) in &courts {
        let players: Vec<String> = sessions
            .iter()
            .filter(|(c, _, _)| c == number)
            .map(|(_, _, u)| u.clone())
            .collect();
        let ends_at = sessions.iter().find(|(c, _, _)| c == number).map(|(_, e, _)| *e);
        let seconds_left = ends_at.map(|e| (e - now).num_seconds().max(0));

        let status = if *closed {
            "closed"
        } else if players.len() >= 4 {
            "full"
        } else if !players.is_empty() {
            "half"
        } else {
            "available"
        };

        // Queue groups on this court, dense positions.
        let mut queue_views: Vec<Value> = Vec::new();
        let mut positions: Vec<i32> = queues
            .iter()
            .filter(|(c, _, _)| c == number)
            .map(|(_, p, _)| *p)
            .collect();
        positions.dedup();
        for pos in &positions {
            let members: Vec<String> = queues
                .iter()
                .filter(|(c, p, _)| c == number && p == pos)
                .map(|(_, _, u)| u.clone())
                .collect();
            let eta_minutes = (seconds_left.unwrap_or(0) as f64 / 60.0
                + ((*pos - 1).max(0) as f64) * club.session_minutes as f64)
                .round() as i64;
            queue_views.push(json!({
                "position": pos,
                "size": members.len(),
                "label": group_label(&members),
                "eta_minutes": eta_minutes,
            }));
        }

        let mut view = json!({
            "number": number,
            "status": status,
            "players": players,
            "queue": queue_views,
            "queue_len": positions.len(),
            "queue_depth": club.queue_depth,
        });
        if let Some(s) = seconds_left {
            view["seconds_left"] = json!(s);
        }
        if *closed {
            if let Some(r) = closed_reason {
                view["closed_reason"] = json!(r);
            }
        }
        court_views.push(view);
    }

    Ok(json!({
        "club": {
            "name": club.name,
            "slug": club.slug,
            "brand_color": club.brand_color,
            "kiosk_theme": club.kiosk_theme,
            "court_count": club.court_count,
            "session_minutes": club.session_minutes,
            "queue_depth": club.queue_depth,
            "opens_at": club.opens_at.format("%H:%M").to_string(),
            "closes_at": club.closes_at.format("%H:%M").to_string(),
            "open_now": club.open_now(),
        },
        "courts": court_views,
        "now": now.to_rfc3339(),
    }))
}

// ---- word-slug generators ---------------------------------------------------

// Desk-friendly word lists. Sizes matter for the password space: kiosk
// passwords draw adj x noun x 2 digits (>= 110 * 110 * 90 ≈ 1.09M
// combinations, backed by the per-username failure lockout in otp.rs), and
// admin temp passwords draw 4 words from the combined 200+ list + 2 digits.
const ADJECTIVES: &[&str] = &[
    "swift", "brave", "calm", "keen", "bold", "spry", "zesty", "merry", "lucky", "sunny",
    "rapid", "quiet", "witty", "eager", "noble", "plucky", "vivid", "breezy", "chirpy", "dandy",
    "agile", "amber", "ample", "artful", "azure", "balmy", "blithe", "bonny", "bouncy", "brainy",
    "brisk", "bubbly", "candid", "cheery", "chipper", "civil", "classy", "clever", "comfy", "coral",
    "cosmic", "crafty", "crisp", "daring", "dapper", "deft", "dewy", "dreamy", "driven", "dusky",
    "early", "earnest", "fabled", "fancy", "feisty", "fleet", "floral", "frosty", "gentle", "giddy",
    "gilded", "glad", "gleeful", "glossy", "golden", "grand", "groovy", "handy", "happy", "hardy",
    "hearty", "honest", "humble", "ivory", "jaunty", "jazzy", "jolly", "jovial", "jumpy", "kindly",
    "limber", "lively", "loyal", "lunar", "mellow", "mighty", "minty", "misty", "modest", "nifty",
    "nimble", "peachy", "peppy", "perky", "plush", "polar", "poised", "proud", "punchy", "quirky",
    "rosy", "rustic", "sandy", "sassy", "shiny", "silken", "silver", "sleek", "smart", "snappy",
    "snazzy", "solar", "spiffy", "zippy", "stellar", "stout", "sturdy", "tidy", "trusty", "upbeat",
];
const NOUNS: &[&str] = &[
    "heron", "falcon", "otter", "badger", "lynx", "puffin", "gecko", "marmot", "wombat", "ibis",
    "osprey", "swiftlet", "drake", "magpie", "beaver", "tapir", "kestrel", "wren", "stoat", "civet",
    "acorn", "alder", "aspen", "bantam", "beacon", "birch", "bison", "bluejay", "bobcat", "bonsai",
    "bramble", "briar", "brook", "bunting", "burrow", "canary", "caribou", "cedar", "cheetah", "chinook",
    "clover", "comet", "condor", "cosmos", "cougar", "coyote", "crane", "cricket", "cypress", "dolphin",
    "dune", "eagle", "egret", "elk", "ember", "ermine", "fennec", "fern", "finch", "fjord",
    "fox", "gazelle", "gibbon", "ginkgo", "glacier", "grouse", "gull", "harbor", "hawk", "hazel",
    "heath", "hedgehog", "hollow", "ibex", "iguana", "jackal", "jay", "juniper", "kiwi", "koala",
    "lagoon", "lark", "laurel", "lemur", "linnet", "lotus", "mango", "maple", "marlin", "meadow",
    "merlin", "mesa", "mink", "minnow", "mole", "moose", "moth", "narwhal", "newt", "nutmeg",
    "ocelot", "oriole", "panda", "pebble", "pelican", "penguin", "pine", "plover", "quail", "raven",
    "reef", "ridge", "robin", "rowan", "sable", "sparrow", "starling", "summit", "teal", "willow",
];

fn pick(list: &'static [&'static str]) -> &'static str {
    use rand::Rng;
    list[rand::thread_rng().gen_range(0..list.len())]
}

/// One word drawn uniformly from the combined adjective + noun list.
fn pick_any_word() -> &'static str {
    use rand::Rng;
    let i = rand::thread_rng().gen_range(0..ADJECTIVES.len() + NOUNS.len());
    if i < ADJECTIVES.len() { ADJECTIVES[i] } else { NOUNS[i - ADJECTIVES.len()] }
}

fn two_digits() -> u32 {
    use rand::Rng;
    rand::thread_rng().gen_range(10..100)
}

/// Kiosk username slip: "<adj><noun>-NN", e.g. "swiftheron-42".
pub fn generate_username() -> String {
    format!("{}{}-{}", pick(ADJECTIVES), pick(NOUNS), two_digits())
}

/// Kiosk password slip: "word-word-NN". Desk-friendly shape over a >= 1M
/// space; brute force is cut off by the per-username lockout (otp.rs).
pub fn generate_password() -> String {
    format!("{}-{}-{}", pick(ADJECTIVES), pick(NOUNS), two_digits())
}

/// Club-admin temp password: 4 words from the combined 200+ list + 2 digits.
/// Admins type it exactly once (must_change forces a rotation on first login),
/// so length wins over convenience here.
pub fn generate_admin_password() -> String {
    format!(
        "{}-{}-{}-{}-{}",
        pick_any_word(),
        pick_any_word(),
        pick_any_word(),
        pick_any_word(),
        two_digits()
    )
}

// ---- tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // These run against Postgres (DATABASE_URL), each in its own ephemeral
    // database with all migrations applied — same setup CI uses.

    async fn seed_club(db: &PgPool) -> ClubRow {
        seed_club_with(db, true).await
    }

    async fn seed_club_with(db: &PgPool, auto_extend: bool) -> ClubRow {
        let club: ClubRow = sqlx::query_as(&format!(
            "INSERT INTO clubs (slug, name, court_count, session_minutes, queue_depth, auto_extend,
                                opens_at, closes_at)
             VALUES ('test-club', 'Test Club', 5, 45, 3, $1, '00:00', '23:59')
             RETURNING {CLUB_COLUMNS}"
        ))
        .bind(auto_extend)
        .fetch_one(db)
        .await
        .unwrap();
        for n in 1..=5 {
            sqlx::query("INSERT INTO club_courts (club_id, number) VALUES ($1, $2)")
                .bind(club.id)
                .bind(n)
                .execute(db)
                .await
                .unwrap();
        }
        club
    }

    async fn seed_cred(db: &PgPool, club: &ClubRow, username: &str) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO club_credentials (club_id, username, password) VALUES ($1, $2, 'pw')
             RETURNING id",
        )
        .bind(club.id)
        .bind(username)
        .fetch_one(db)
        .await
        .unwrap()
    }

    async fn revoke(db: &PgPool, id: Uuid) {
        sqlx::query("UPDATE club_credentials SET status = 'revoked' WHERE id = $1")
            .bind(id)
            .execute(db)
            .await
            .unwrap();
    }

    /// Insert an active session whose timer has already hit zero.
    async fn seed_expired_session(db: &PgPool, club: &ClubRow, court: i32, creds: &[Uuid]) -> Uuid {
        let sid: Uuid = sqlx::query_scalar(
            "INSERT INTO court_sessions (club_id, court_number, started_at, ends_at)
             VALUES ($1, $2, NOW() - INTERVAL '46 minutes', NOW() - INTERVAL '1 minute')
             RETURNING id",
        )
        .bind(club.id)
        .bind(court)
        .fetch_one(db)
        .await
        .unwrap();
        for c in creds {
            sqlx::query("INSERT INTO session_players (session_id, credential_id) VALUES ($1, $2)")
                .bind(sid)
                .bind(c)
                .execute(db)
                .await
                .unwrap();
        }
        sid
    }

    async fn seed_queue_group(db: &PgPool, club: &ClubRow, court: i32, pos: i32, creds: &[Uuid]) -> Uuid {
        let qid: Uuid = sqlx::query_scalar(
            "INSERT INTO court_queues (club_id, court_number, position) VALUES ($1, $2, $3)
             RETURNING id",
        )
        .bind(club.id)
        .bind(court)
        .bind(pos)
        .fetch_one(db)
        .await
        .unwrap();
        for c in creds {
            sqlx::query("INSERT INTO queue_players (queue_id, credential_id) VALUES ($1, $2)")
                .bind(qid)
                .bind(c)
                .execute(db)
                .await
                .unwrap();
        }
        qid
    }

    fn creds(pairs: &[&str]) -> Vec<PlayerCred> {
        pairs
            .iter()
            .map(|u| PlayerCred { username: u.to_string(), password: "pw".to_string() })
            .collect()
    }

    async fn active_session_players(db: &PgPool, club: &ClubRow, court: i32) -> Vec<Uuid> {
        sqlx::query_scalar(
            "SELECT sp.credential_id FROM session_players sp
             JOIN court_sessions cs ON cs.id = sp.session_id
             WHERE cs.club_id = $1 AND cs.court_number = $2 AND cs.status = 'active'
             ORDER BY sp.credential_id",
        )
        .bind(club.id)
        .bind(court)
        .fetch_all(db)
        .await
        .unwrap()
    }

    // ---- engine ----

    #[sqlx::test]
    async fn engine_promotes_queue_group_on_expiry(db: PgPool) {
        let club = seed_club(&db).await;
        let a = seed_cred(&db, &club, "a1").await;
        let b = seed_cred(&db, &club, "b1").await;
        let c = seed_cred(&db, &club, "c1").await;
        let d = seed_cred(&db, &club, "d1").await;
        let old = seed_expired_session(&db, &club, 1, &[a, b]).await;
        seed_queue_group(&db, &club, 1, 1, &[c, d]).await;

        let outcome = expire_court(&db, club.id, 1).await.unwrap();
        assert_eq!(outcome, Some(EngineOutcome::Promoted { dropped: 0 }));

        let old_status: String = sqlx::query_scalar("SELECT status FROM court_sessions WHERE id = $1")
            .bind(old)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(old_status, "done");

        let mut promoted = active_session_players(&db, &club, 1).await;
        promoted.sort();
        let mut expected = vec![c, d];
        expected.sort();
        assert_eq!(promoted, expected, "queue group must now hold the court");

        let queue_len: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM court_queues WHERE club_id = $1")
            .bind(club.id)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(queue_len, 0);

        // The promoted session gets a full fresh timer.
        let ends_at: DateTime<Utc> = sqlx::query_scalar(
            "SELECT ends_at FROM court_sessions WHERE club_id = $1 AND status = 'active'",
        )
        .bind(club.id)
        .fetch_one(&db)
        .await
        .unwrap();
        let left = (ends_at - time::now()).num_minutes();
        assert!((43..=45).contains(&left), "expected ~45 minutes, got {left}");
    }

    #[sqlx::test]
    async fn engine_drops_revoked_group_and_promotes_next(db: PgPool) {
        let club = seed_club(&db).await;
        let a = seed_cred(&db, &club, "a1").await;
        let b = seed_cred(&db, &club, "b1").await;
        let bad = seed_cred(&db, &club, "bad").await;
        let bad2 = seed_cred(&db, &club, "bad2").await;
        let c = seed_cred(&db, &club, "c1").await;
        let d = seed_cred(&db, &club, "d1").await;
        let e = seed_cred(&db, &club, "e1").await;
        let f = seed_cred(&db, &club, "f1").await;
        revoke(&db, bad).await;

        seed_expired_session(&db, &club, 2, &[a, b]).await;
        seed_queue_group(&db, &club, 2, 1, &[bad, bad2]).await; // one revoked → whole group drops
        seed_queue_group(&db, &club, 2, 2, &[c, d]).await;
        seed_queue_group(&db, &club, 2, 3, &[e, f]).await;

        let outcome = expire_court(&db, club.id, 2).await.unwrap();
        assert_eq!(outcome, Some(EngineOutcome::Promoted { dropped: 1 }));

        let mut on_court = active_session_players(&db, &club, 2).await;
        on_court.sort();
        let mut expected = vec![c, d];
        expected.sort();
        assert_eq!(on_court, expected, "second group must be promoted past the revoked one");

        // Remaining group renumbered to a dense position 1.
        let rest: Vec<(i32,)> = sqlx::query_as(
            "SELECT position FROM court_queues WHERE club_id = $1 ORDER BY position",
        )
        .bind(club.id)
        .fetch_all(&db)
        .await
        .unwrap();
        assert_eq!(rest, vec![(1,)]);
    }

    #[sqlx::test]
    async fn engine_auto_extends_when_queue_empty(db: PgPool) {
        let club = seed_club(&db).await; // auto_extend = true
        let a = seed_cred(&db, &club, "a1").await;
        let b = seed_cred(&db, &club, "b1").await;
        let sid = seed_expired_session(&db, &club, 3, &[a, b]).await;

        let outcome = expire_court(&db, club.id, 3).await.unwrap();
        assert_eq!(outcome, Some(EngineOutcome::Extended));

        let (status, extensions, ends_at): (String, i32, DateTime<Utc>) = sqlx::query_as(
            "SELECT status, extensions, ends_at FROM court_sessions WHERE id = $1",
        )
        .bind(sid)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(status, "active");
        assert_eq!(extensions, 1);
        // ends_at += session_minutes from the OLD deadline (1 min ago) → ~44 left.
        let left = (ends_at - time::now()).num_minutes();
        assert!((42..=44).contains(&left), "expected ~44 minutes left, got {left}");

        // A second pass does nothing until the new deadline hits.
        assert_eq!(expire_court(&db, club.id, 3).await.unwrap(), None);
    }

    #[sqlx::test]
    async fn engine_clears_court_without_auto_extend(db: PgPool) {
        let club = seed_club_with(&db, false).await;
        let a = seed_cred(&db, &club, "a1").await;
        let b = seed_cred(&db, &club, "b1").await;
        let sid = seed_expired_session(&db, &club, 1, &[a, b]).await;

        let outcome = expire_court(&db, club.id, 1).await.unwrap();
        assert_eq!(outcome, Some(EngineOutcome::Cleared));
        let status: String = sqlx::query_scalar("SELECT status FROM court_sessions WHERE id = $1")
            .bind(sid)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(status, "done");
        assert!(active_session_players(&db, &club, 1).await.is_empty());
    }

    #[sqlx::test]
    async fn engine_all_queue_groups_revoked_falls_through_to_empty_queue_rule(db: PgPool) {
        let club = seed_club(&db).await; // auto_extend = true
        let a = seed_cred(&db, &club, "a1").await;
        let b = seed_cred(&db, &club, "b1").await;
        let bad = seed_cred(&db, &club, "bad").await;
        let bad2 = seed_cred(&db, &club, "bad2").await;
        revoke(&db, bad).await;
        let sid = seed_expired_session(&db, &club, 1, &[a, b]).await;
        seed_queue_group(&db, &club, 1, 1, &[bad, bad2]).await;

        // Only queue group dropped → queue empties → auto-extend rule applies.
        let outcome = expire_court(&db, club.id, 1).await.unwrap();
        assert_eq!(outcome, Some(EngineOutcome::Extended));
        let status: String = sqlx::query_scalar("SELECT status FROM court_sessions WHERE id = $1")
            .bind(sid)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(status, "active");
        let queue_len: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM court_queues WHERE club_id = $1")
            .bind(club.id)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(queue_len, 0);
    }

    // ---- take / join / queue validation ----

    fn validation_errors(err: ActionError) -> Vec<CredError> {
        match err {
            ActionError::Validation(errors) => errors,
            other => panic!("expected validation errors, got {other:?}"),
        }
    }

    #[sqlx::test]
    async fn take_rejects_bad_credentials_with_per_field_codes(db: PgPool) {
        let club = seed_club(&db).await;
        seed_cred(&db, &club, "good").await;
        let rev = seed_cred(&db, &club, "gone").await;
        revoke(&db, rev).await;

        let players = vec![
            PlayerCred { username: "good".into(), password: "wrong".into() },
            PlayerCred { username: "ghost".into(), password: "pw".into() },
            PlayerCred { username: "gone".into(), password: "pw".into() },
            PlayerCred { username: "good".into(), password: "pw".into() },
        ];
        let errs = validation_errors(take_court(&db, &club, 1, &players).await.unwrap_err());
        assert_eq!(errs.len(), 4);
        assert_eq!(errs[0].code, "bad_password");
        assert_eq!(errs[1].code, "not_found");
        assert_eq!(errs[2].code, "revoked");
        assert_eq!(errs[3].code, "duplicate", "same username twice in one group");

        // Nothing was created.
        assert!(active_session_players(&db, &club, 1).await.is_empty());
    }

    #[sqlx::test]
    async fn take_rejects_group_of_three(db: PgPool) {
        let club = seed_club(&db).await;
        for u in ["a1", "b1", "c1"] {
            seed_cred(&db, &club, u).await;
        }
        match take_court(&db, &club, 1, &creds(&["a1", "b1", "c1"])).await {
            Err(ActionError::Court(msg)) => assert!(msg.contains("exactly 2 or 4"), "{msg}"),
            other => panic!("group of 3 must be rejected, got {other:?}"),
        }
    }

    #[sqlx::test]
    async fn join_requires_exactly_two_and_a_half_court(db: PgPool) {
        let club = seed_club(&db).await;
        for u in ["a1", "b1", "c1", "d1", "e1", "f1"] {
            seed_cred(&db, &club, u).await;
        }
        take_court(&db, &club, 1, &creds(&["a1", "b1"])).await.unwrap();

        // Join-half is exactly 2 — never 1 or 3.
        assert!(matches!(
            join_court(&db, &club, 1, &creds(&["c1"])).await,
            Err(ActionError::Court(_))
        ));
        // Valid join fills the court…
        join_court(&db, &club, 1, &creds(&["c1", "d1"])).await.unwrap();
        assert_eq!(active_session_players(&db, &club, 1).await.len(), 4);
        // …after which the court is full and cannot be joined again.
        assert!(matches!(
            join_court(&db, &club, 1, &creds(&["e1", "f1"])).await,
            Err(ActionError::Court(_))
        ));
    }

    #[sqlx::test]
    async fn double_use_is_rejected_across_courts_and_queues(db: PgPool) {
        let club = seed_club(&db).await;
        for u in ["a1", "b1", "c1", "d1", "e1", "f1", "g1", "h1"] {
            seed_cred(&db, &club, u).await;
        }
        take_court(&db, &club, 1, &creds(&["a1", "b1", "c1", "d1"])).await.unwrap();

        // a1 is on court 1 → taking court 2 with it fails with on_court + court number.
        let errs =
            validation_errors(take_court(&db, &club, 2, &creds(&["a1", "e1"])).await.unwrap_err());
        assert_eq!(errs, vec![CredError { username: "a1".into(), code: "on_court", court_number: Some(1) }]);

        // e1+f1 queue behind the full court 1; then e1 can't queue (or play) anywhere else.
        queue_court(&db, &club, 1, &creds(&["e1", "f1"])).await.unwrap();
        let errs =
            validation_errors(take_court(&db, &club, 2, &creds(&["e1", "g1"])).await.unwrap_err());
        assert_eq!(errs, vec![CredError { username: "e1".into(), code: "in_queue", court_number: Some(1) }]);
    }

    #[sqlx::test]
    async fn queue_requires_full_court_and_respects_depth(db: PgPool) {
        let club = seed_club(&db).await; // queue_depth = 3
        for u in ["a1", "b1", "c1", "d1", "e1", "f1", "g1", "h1", "i1", "j1", "k1", "l1"] {
            seed_cred(&db, &club, u).await;
        }

        // Empty court: queueing makes no sense.
        assert!(matches!(
            queue_court(&db, &club, 1, &creds(&["e1", "f1"])).await,
            Err(ActionError::Court(_))
        ));
        // Half court: join, don't queue.
        take_court(&db, &club, 1, &creds(&["a1", "b1"])).await.unwrap();
        assert!(matches!(
            queue_court(&db, &club, 1, &creds(&["e1", "f1"])).await,
            Err(ActionError::Court(_))
        ));
        join_court(&db, &club, 1, &creds(&["c1", "d1"])).await.unwrap();

        // Full court: positions hand out densely until queue_depth.
        assert_eq!(queue_court(&db, &club, 1, &creds(&["e1", "f1"])).await.unwrap(), 1);
        assert_eq!(queue_court(&db, &club, 1, &creds(&["g1", "h1"])).await.unwrap(), 2);
        assert_eq!(queue_court(&db, &club, 1, &creds(&["i1", "j1"])).await.unwrap(), 3);
        match queue_court(&db, &club, 1, &creds(&["k1", "l1"])).await {
            Err(ActionError::Court(msg)) => assert!(msg.contains("queue is full"), "{msg}"),
            other => panic!("4th group must be rejected at depth 3, got {other:?}"),
        }
    }

    #[sqlx::test]
    async fn take_rejects_closed_and_busy_courts(db: PgPool) {
        let club = seed_club(&db).await;
        for u in ["a1", "b1", "c1", "d1"] {
            seed_cred(&db, &club, u).await;
        }
        sqlx::query(
            "UPDATE club_courts SET closed = TRUE, closed_reason = 'maintenance'
             WHERE club_id = $1 AND number = 2",
        )
        .bind(club.id)
        .execute(&db)
        .await
        .unwrap();

        assert!(matches!(
            take_court(&db, &club, 2, &creds(&["a1", "b1"])).await,
            Err(ActionError::Court(_))
        ));
        take_court(&db, &club, 1, &creds(&["a1", "b1"])).await.unwrap();
        assert!(matches!(
            take_court(&db, &club, 1, &creds(&["c1", "d1"])).await,
            Err(ActionError::Court(_))
        ));
    }

    #[test]
    fn group_labels_match_spec() {
        assert_eq!(group_label(&["ann".into(), "bob".into()]), "ann pair");
        assert_eq!(
            group_label(&["ann".into(), "bob".into(), "cid".into(), "dot".into()]),
            "ann + 3 others"
        );
    }

    // ---- shrink / resize ----

    #[sqlx::test]
    async fn resize_shrink_blocked_while_removed_court_in_play(db: PgPool) {
        let club = seed_club(&db).await; // 5 courts
        for u in ["a1", "b1"] {
            seed_cred(&db, &club, u).await;
        }
        take_court(&db, &club, 5, &creds(&["a1", "b1"])).await.unwrap();

        let mut tx = db.begin().await.unwrap();
        match resize_courts(&mut tx, club.id, 3).await {
            Err(ActionError::Court(msg)) => assert!(msg.contains("still have games"), "{msg}"),
            other => panic!("shrink over an active session must be refused, got {other:?}"),
        }
        tx.rollback().await.unwrap();

        // Nothing was removed by the refused shrink.
        let court_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM club_courts WHERE club_id = $1")
                .bind(club.id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(court_rows, 5);
    }

    #[sqlx::test]
    async fn resize_shrink_allowed_when_removed_courts_idle(db: PgPool) {
        let club = seed_club(&db).await; // 5 courts
        let a = seed_cred(&db, &club, "a1").await;
        let b = seed_cred(&db, &club, "b1").await;
        // A stale queue group on a removed court is released by the shrink.
        seed_queue_group(&db, &club, 4, 1, &[a, b]).await;

        let mut tx = db.begin().await.unwrap();
        resize_courts(&mut tx, club.id, 3).await.unwrap();
        tx.commit().await.unwrap();

        let court_rows: Vec<(i32,)> = sqlx::query_as(
            "SELECT number FROM club_courts WHERE club_id = $1 ORDER BY number",
        )
        .bind(club.id)
        .fetch_all(&db)
        .await
        .unwrap();
        assert_eq!(court_rows, vec![(1,), (2,), (3,)]);
        let count: i32 = sqlx::query_scalar("SELECT court_count FROM clubs WHERE id = $1")
            .bind(club.id)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(count, 3);
        let queues: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM court_queues WHERE club_id = $1")
            .bind(club.id)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(queues, 0, "queues on removed courts must be released");

        // Grow back re-seeds the missing rows.
        let mut tx = db.begin().await.unwrap();
        resize_courts(&mut tx, club.id, 6).await.unwrap();
        tx.commit().await.unwrap();
        let court_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM club_courts WHERE club_id = $1")
                .bind(club.id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(court_rows, 6);
    }

    // ---- expiry edge cases ----

    #[sqlx::test]
    async fn expire_drains_orphan_session_on_missing_court_row(db: PgPool) {
        let club = seed_club(&db).await; // auto_extend = true, courts 1..5
        let a = seed_cred(&db, &club, "a1").await;
        let b = seed_cred(&db, &club, "b1").await;
        // Orphan: an active session on a court with no club_courts row (the
        // shape a lost shrink race would leave behind).
        let sid = seed_expired_session(&db, &club, 9, &[a, b]).await;

        let outcome = expire_court(&db, club.id, 9).await.unwrap();
        assert_eq!(
            outcome,
            Some(EngineOutcome::Cleared),
            "missing court must default to closed and drain, never auto-extend"
        );
        let status: String = sqlx::query_scalar("SELECT status FROM court_sessions WHERE id = $1")
            .bind(sid)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(status, "done");
    }

    #[sqlx::test]
    async fn revoked_member_blocks_auto_extend(db: PgPool) {
        let club = seed_club(&db).await; // auto_extend = true
        let a = seed_cred(&db, &club, "a1").await;
        let b = seed_cred(&db, &club, "b1").await;
        revoke(&db, a).await;
        let sid = seed_expired_session(&db, &club, 2, &[a, b]).await;

        let outcome = expire_court(&db, club.id, 2).await.unwrap();
        assert_eq!(
            outcome,
            Some(EngineOutcome::Cleared),
            "a group holding a revoked credential must not be extended"
        );
        let status: String = sqlx::query_scalar("SELECT status FROM court_sessions WHERE id = $1")
            .bind(sid)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(status, "done");
    }

    #[sqlx::test]
    async fn expired_unresolved_session_refuses_take_and_join(db: PgPool) {
        let club = seed_club(&db).await;
        let a = seed_cred(&db, &club, "a1").await;
        let b = seed_cred(&db, &club, "b1").await;
        for u in ["c1", "d1"] {
            seed_cred(&db, &club, u).await;
        }
        seed_expired_session(&db, &club, 1, &[a, b]).await;

        match join_court(&db, &club, 1, &creds(&["c1", "d1"])).await {
            Err(ActionError::Court(msg)) => assert!(msg.contains("finishing up"), "{msg}"),
            other => panic!("join on an expired session must be refused, got {other:?}"),
        }
        match take_court(&db, &club, 1, &creds(&["c1", "d1"])).await {
            Err(ActionError::Court(msg)) => assert!(msg.contains("finishing up"), "{msg}"),
            other => panic!("take on an expired session must be refused, got {other:?}"),
        }
    }

    #[sqlx::test]
    async fn take_maps_unique_violation_to_friendly_conflict(db: PgPool) {
        let club = seed_club(&db).await;
        for u in ["a1", "b1"] {
            seed_cred(&db, &club, u).await;
        }
        // Simulate a writer that slipped the lock discipline: an uncommitted
        // active session on court 1, held open while take_court runs. take's
        // court_state can't see it (read committed), so its insert blocks on
        // the partial unique index and fails once this commits.
        let mut tx = db.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO court_sessions (club_id, court_number, started_at, ends_at)
             VALUES ($1, 1, NOW(), NOW() + INTERVAL '45 minutes')",
        )
        .bind(club.id)
        .execute(&mut *tx)
        .await
        .unwrap();

        let db2 = db.clone();
        let club2 = club.clone();
        let handle =
            tokio::spawn(async move { take_court(&db2, &club2, 1, &creds(&["a1", "b1"])).await });
        // Let take_court get past its state check and block on the index.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        tx.commit().await.unwrap();

        match handle.await.unwrap() {
            Err(ActionError::Court(msg)) => assert!(msg.contains("just taken"), "{msg}"),
            other => panic!("expected the friendly just-taken conflict, got {other:?}"),
        }
    }

    // ---- kiosk password-guess lockout ----

    #[sqlx::test]
    async fn kiosk_username_locks_after_ten_bad_passwords(_db: PgPool) {
        dotenvy::dotenv().ok();
        let Ok(url) = std::env::var("REDIS_URL") else {
            eprintln!("REDIS_URL not set — skipping kiosk lockout test");
            return;
        };
        let Some(redis) = crate::connect_redis(&url).await else {
            eprintln!("Redis unreachable — skipping kiosk lockout test");
            return;
        };
        let redis = Some(redis);
        // Fresh club id per run keeps the Redis keys isolated between runs.
        let club_id = Uuid::new_v4();
        let user = "swiftheron-42";

        for i in 1..=9 {
            let locked_now =
                crate::otp::note_kiosk_bad_password(redis.clone(), club_id, user).await;
            assert!(!locked_now, "attempt {i} must not lock yet");
            assert!(
                !crate::otp::is_kiosk_username_locked(redis.clone(), club_id, user).await,
                "attempt {i} must not lock yet"
            );
        }
        assert!(
            crate::otp::note_kiosk_bad_password(redis.clone(), club_id, user).await,
            "10th wrong password crosses the threshold"
        );
        assert!(crate::otp::is_kiosk_username_locked(redis.clone(), club_id, user).await);
        // Other usernames (and other clubs) are unaffected.
        assert!(!crate::otp::is_kiosk_username_locked(redis.clone(), club_id, "other-user").await);
        assert!(
            !crate::otp::is_kiosk_username_locked(redis.clone(), Uuid::new_v4(), user).await
        );
    }

    // ---- generators ----

    #[test]
    fn password_spaces_meet_minimums() {
        use std::collections::HashSet;
        // Kiosk: adj x noun x 2 digits must clear 1M combinations.
        assert!(ADJECTIVES.len() >= 110, "adjective list shrank");
        assert!(NOUNS.len() >= 110, "noun list shrank");
        assert!(ADJECTIVES.len() * NOUNS.len() * 90 >= 1_000_000);
        // Admin temp passwords draw from the combined 200+ word list.
        assert!(ADJECTIVES.len() + NOUNS.len() >= 200);
        // No duplicate words (a typo here would silently shrink the space).
        assert_eq!(ADJECTIVES.iter().collect::<HashSet<_>>().len(), ADJECTIVES.len());
        assert_eq!(NOUNS.iter().collect::<HashSet<_>>().len(), NOUNS.len());

        assert_eq!(generate_password().split('-').count(), 3);
        assert_eq!(generate_admin_password().split('-').count(), 5, "4 words + 2 digits");
    }
}
