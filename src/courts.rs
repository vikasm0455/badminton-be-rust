//! Courts v2 domain logic: the per-court state machine (take / join / queue /
//! leave), the day-pass credential model, walk-in + member check-in stations,
//! the kiosk board snapshot, and the expiry engine.
//!
//! Concurrency contract (see migrations/0009_clubs.sql + 0010_clubs_v2.sql):
//! every mutation of a court's state runs inside a transaction that first takes
//! `pg_advisory_xact_lock(hashtext(club_id || ':' || court_number))`, so a
//! court has exactly one writer at a time; anything that changes a credential's
//! placement then takes the credential advisory locks in ONE sorted batch.
//! Handlers and the engine both go through this module; HTTP-only concerns
//! (auth, envelopes, open-hours gate) stay in routes/clubs.rs so these
//! functions are testable against a bare pool.

use chrono::{DateTime, NaiveDate, NaiveTime, Utc};
use chrono_tz::Tz;
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
    pub timezone: String,
    pub created_at: DateTime<Utc>,
}

pub const CLUB_COLUMNS: &str = "id, slug, name, brand_color, court_count, session_minutes, \
     queue_depth, auto_extend, opens_at, closes_at, kiosk_theme, status, timezone, created_at";

pub async fn club_by_slug(db: &PgPool, slug: &str) -> Result<Option<ClubRow>, sqlx::Error> {
    sqlx::query_as::<_, ClubRow>(&format!("SELECT {CLUB_COLUMNS} FROM clubs WHERE slug = $1"))
        .bind(slug)
        .fetch_optional(db)
        .await
}

/// Parse an IANA timezone name ("America/Los_Angeles"). The API validates
/// through this exact function, so a stored value can always be re-parsed.
pub fn parse_timezone(s: &str) -> Option<Tz> {
    s.trim().parse().ok()
}

impl ClubRow {
    /// The club's timezone. Stored values are chrono-tz-validated at write
    /// time; a corrupt row falls back to the platform default rather than
    /// bricking the club.
    pub fn tz(&self) -> Tz {
        parse_timezone(&self.timezone).unwrap_or(time::APP_TZ)
    }

    /// Today's calendar date in the CLUB's timezone — the day a day pass is
    /// valid for. Never the server-local date.
    pub fn today(&self) -> NaiveDate {
        time::now().with_timezone(&self.tz()).date_naive()
    }

    /// Kiosk actions are allowed only within opening hours, measured on the
    /// club's own wall clock (v1 used server-local time — fixed in v2).
    pub fn open_now(&self) -> bool {
        let now = time::now().with_timezone(&self.tz()).time();
        self.opens_at <= now && now < self.closes_at
    }
}

// ---- day-pass validity ------------------------------------------------------

/// THE validity rule (v2 day-pass model), used by every code path that asks
/// "may this credential play right now": kiosk action validation, the engine's
/// promotion drop-check, and the auto-extend guard. A pass is usable iff it is
/// active AND issued for today in the club's timezone — expiry needs no
/// midnight sweep because expired simply stops satisfying this predicate
/// (expired == revoked semantics).
pub fn credential_usable(status: &str, valid_date: NaiveDate, today: NaiveDate) -> bool {
    status == "active" && valid_date == today
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
    /// 'not_found' | 'expired' | 'revoked' | 'bad_password' | 'on_court' |
    /// 'in_queue' | 'duplicate' | 'not_on_court' | 'not_in_queue'
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

/// Serialize walk-in signup and member-add on one (club, username): the two
/// paths are a cross-TABLE check-then-insert pair (walkin_create checks
/// club_members then inserts club_credentials; admin_add_member checks
/// club_credentials then inserts club_members) with no constraint spanning the
/// tables, so without this lock they can interleave into an active member and
/// a same-day walk-in sharing one username — which bricks the member's
/// check-in for the day.
///
/// LOCK ORDER: the global advisory-lock order is clubs-row FOR UPDATE ->
/// username -> courts ascending -> credentials sorted. Today the only paths
/// taking this lock (walkin_create, admin_add_member) take NO other advisory
/// locks, so it is their only lock. If a future path ever needs it alongside
/// court/credential locks, it MUST be taken BEFORE them to keep the global
/// order acyclic.
pub(crate) async fn lock_username(
    tx: &mut Transaction<'_, Postgres>,
    club_id: Uuid,
    username: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('uname:' || $1 || ':' || lower($2)))")
        .bind(club_id.to_string())
        .bind(username)
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

/// How strictly resolve_players applies the day-validity rule.
#[derive(Clone, Copy, PartialEq)]
enum ResolveMode {
    /// take/join/queue: an out-of-date pass is refused ("expired").
    Play,
    /// leave court / leave queue: status + password are still verified, but an
    /// ACTIVE pass whose valid_date rolled past midnight may still sign off —
    /// leaving only removes placement and can never double-place, so a group
    /// physically on court at 00:01 must not be locked onto it.
    Leave,
}

/// Phase-1 identity resolution shared by every credential-carrying kiosk
/// action (take/join/queue AND leave): existence, day-pass validity
/// (credential_usable, per `mode`), and password — collecting ALL failures so
/// the kiosk can mark each field. Does NOT take credential locks or check
/// placement.
async fn resolve_players(
    tx: &mut Transaction<'_, Postgres>,
    club_id: Uuid,
    players: &[PlayerCred],
    today: NaiveDate,
    mode: ResolveMode,
    errors: &mut Vec<CredError>,
) -> Result<Vec<(String, Uuid)>, sqlx::Error> {
    let mut resolved: Vec<(String, Uuid)> = Vec::new();
    let mut seen: Vec<String> = Vec::new();

    for p in players {
        let username = p.username.trim().to_string();
        let fail = |code: &'static str| CredError {
            username: username.clone(),
            code,
            court_number: None,
        };
        if seen.iter().any(|s| s.eq_ignore_ascii_case(&username)) {
            errors.push(fail("duplicate"));
            continue;
        }
        seen.push(username.clone());

        // Usernames recycle daily, so several rows can share one username —
        // the newest pass is the one the player is holding.
        let row: Option<(Uuid, String, String, NaiveDate)> = sqlx::query_as(
            "SELECT id, password, status, valid_date FROM club_credentials
             WHERE club_id = $1 AND username = $2
             ORDER BY valid_date DESC LIMIT 1",
        )
        .bind(club_id)
        .bind(&username)
        .fetch_optional(&mut **tx)
        .await?;
        let Some((id, password, status, valid_date)) = row else {
            errors.push(fail("not_found"));
            continue;
        };
        if !credential_usable(&status, valid_date, today) {
            if status != "active" {
                // Revoked is dead in every mode.
                errors.push(fail("revoked"));
                continue;
            }
            // Same single validity rule as the engine: an out-of-date pass is
            // as dead as a revoked one for PLAY — but leave paths let it
            // through (see ResolveMode::Leave).
            if mode == ResolveMode::Play {
                errors.push(fail("expired"));
                continue;
            }
        }
        if password != p.password.trim() {
            errors.push(fail("bad_password"));
            continue;
        }
        resolved.push((username, id));
    }
    Ok(resolved)
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
    today: NaiveDate,
) -> Result<Vec<Uuid>, ActionError> {
    let mut errors: Vec<CredError> = Vec::new();
    let resolved =
        resolve_players(tx, club_id, players, today, ResolveMode::Play, &mut errors).await?;

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

/// SQL for the COMPUTED closed state (v2): the legacy manual bool OR an
/// in-progress timed-closure window. Used identically by action validation,
/// the engine, and the board so they can never disagree.
pub const COURT_CLOSED_SQL: &str =
    "(closed OR COALESCE(closed_from <= NOW() AND NOW() < closed_until, FALSE))";

async fn court_state(
    tx: &mut Transaction<'_, Postgres>,
    club: &ClubRow,
    court_number: i32,
) -> Result<CourtState, ActionError> {
    let row: Option<(bool,)> = sqlx::query_as(&format!(
        "SELECT {COURT_CLOSED_SQL} FROM club_courts WHERE club_id = $1 AND number = $2"
    ))
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

    let ids = validate_players(&mut tx, club.id, players, club.today()).await?;
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

    let ids = validate_players(&mut tx, club.id, players, club.today()).await?;
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

    let ids = validate_players(&mut tx, club.id, players, club.today()).await?;
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

// ---- unsign (leave court / leave queue) -------------------------------------

/// What a leave-court call did (drives the handler's message + broadcast).
#[derive(Debug, PartialEq)]
pub struct LeaveOutcome {
    /// The whole group left: session ended (and the queue head was promoted
    /// if one was usable). false = a pair left a 4-group, game continues.
    pub session_ended: bool,
    /// Whether a queue group was promoted onto the freed court.
    pub promoted: bool,
}

/// Leave an active court in a group of exactly 2 or 4 — the mirror of signup:
/// the remainder left on court must be 0 or 2, never 1 or 3. All leavers must
/// authenticate and be players of the court's ACTIVE session. A whole-group
/// leave ends the session and IMMEDIATELY promotes the queue head through the
/// same promote_next (same drop rules, same lock discipline) as the engine.
pub async fn leave_court(
    db: &PgPool,
    club: &ClubRow,
    court_number: i32,
    players: &[PlayerCred],
) -> Result<LeaveOutcome, ActionError> {
    check_group_size(players.len(), &[2, 4])?;
    let today = club.today();
    let mut tx = db.begin().await?;
    lock_court(&mut tx, club.id, court_number).await?;

    // FOR UPDATE so an engine tick racing this leave serializes on the row
    // even if it somehow slipped the court advisory lock.
    let session: Option<(Uuid, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, ends_at FROM court_sessions
         WHERE club_id = $1 AND court_number = $2 AND status = 'active'
         FOR UPDATE",
    )
    .bind(club.id)
    .bind(court_number)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((session_id, ends_at)) = session else {
        return Err(ActionError::Court(format!(
            "Court {court_number} has no game in play."
        )));
    };
    if ends_at <= time::now() {
        // Timer already at zero: the engine owns this court's next state —
        // leaving now could double-promote.
        return Err(finishing_up(court_number));
    }

    let mut errors: Vec<CredError> = Vec::new();
    let resolved =
        resolve_players(&mut tx, club.id, players, today, ResolveMode::Leave, &mut errors).await?;

    // Every leaver must actually be on this court.
    let on_court: Vec<Uuid> = sqlx::query_scalar(
        "SELECT credential_id FROM session_players WHERE session_id = $1",
    )
    .bind(session_id)
    .fetch_all(&mut *tx)
    .await?;
    let mut leaver_ids: Vec<Uuid> = Vec::new();
    for (username, id) in resolved {
        if on_court.contains(&id) {
            leaver_ids.push(id);
        } else {
            errors.push(CredError {
                username,
                code: "not_on_court",
                court_number: Some(court_number),
            });
        }
    }
    if !errors.is_empty() {
        return Err(ActionError::Validation(errors));
    }

    let remainder = on_court.len() - leaver_ids.len();
    if remainder != 0 && remainder != 2 {
        return Err(ActionError::Court(
            "A pair or the whole group can leave — a court is never left with 1 or 3 players."
                .to_string(),
        ));
    }

    if remainder == 2 {
        // A pair steps off a 4-group: the game continues as a half court.
        lock_credentials(&mut tx, &leaver_ids).await?;
        for id in &leaver_ids {
            sqlx::query(
                "DELETE FROM session_players WHERE session_id = $1 AND credential_id = $2",
            )
            .bind(session_id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        return Ok(LeaveOutcome { session_ended: false, promoted: false });
    }

    // Whole group leaves: end the session and promote immediately, under the
    // court lock + ONE sorted credential-lock batch spanning both the leavers
    // and the promoted group (promote_next takes it).
    let closed: bool = sqlx::query_scalar(&format!(
        "SELECT {COURT_CLOSED_SQL} FROM club_courts WHERE club_id = $1 AND number = $2"
    ))
    .bind(club.id)
    .bind(court_number)
    .fetch_optional(&mut *tx)
    .await?
    .unwrap_or(true);
    match promote_next(
        &mut tx,
        club.id,
        court_number,
        club.session_minutes,
        closed,
        today,
        session_id,
        &leaver_ids,
    )
    .await?
    {
        Promotion::Promoted { .. } => {
            tx.commit().await?;
            Ok(LeaveOutcome { session_ended: true, promoted: true })
        }
        Promotion::NotPromoted => {
            // Nobody to promote: just end the session (players stay attached
            // to the done row for history, same as engine expiry).
            lock_credentials(&mut tx, &leaver_ids).await?;
            sqlx::query("UPDATE court_sessions SET status = 'done' WHERE id = $1")
                .bind(session_id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            Ok(LeaveOutcome { session_ended: true, promoted: false })
        }
        // Unreachable while the lock discipline holds (we hold the court lock
        // and just ended the only active session); surface as a soft conflict.
        Promotion::Raced => Err(finishing_up(court_number)),
    }
}

/// Leave a queue in a group of exactly 2 or 4. All leavers must be members of
/// the SAME queue group on this court; the remainder left in the group must be
/// 0 or 2. A whole-group leave removes the group and renumbers the queue.
pub async fn leave_queue(
    db: &PgPool,
    club: &ClubRow,
    court_number: i32,
    players: &[PlayerCred],
) -> Result<bool, ActionError> {
    check_group_size(players.len(), &[2, 4])?;
    let today = club.today();
    let mut tx = db.begin().await?;
    lock_court(&mut tx, club.id, court_number).await?;

    let mut errors: Vec<CredError> = Vec::new();
    let resolved =
        resolve_players(&mut tx, club.id, players, today, ResolveMode::Leave, &mut errors).await?;

    // Each leaver's queue group ON THIS COURT (queue membership only changes
    // under the court lock we hold, so this read is stable).
    let mut group_of: Vec<(Uuid, Uuid)> = Vec::new(); // (credential, queue group)
    for (username, id) in resolved {
        let queued: Option<(Uuid,)> = sqlx::query_as(
            "SELECT q.id FROM queue_players qp
             JOIN court_queues q ON q.id = qp.queue_id
             WHERE qp.credential_id = $1 AND q.club_id = $2 AND q.court_number = $3",
        )
        .bind(id)
        .bind(club.id)
        .bind(court_number)
        .fetch_optional(&mut *tx)
        .await?;
        match queued {
            Some((queue_id,)) => group_of.push((id, queue_id)),
            None => errors.push(CredError {
                username,
                code: "not_in_queue",
                court_number: Some(court_number),
            }),
        }
    }
    if !errors.is_empty() {
        return Err(ActionError::Validation(errors));
    }
    let queue_id = group_of[0].1;
    if group_of.iter().any(|(_, q)| *q != queue_id) {
        return Err(ActionError::Court(
            "Everyone leaving together must be in the same queue group.".to_string(),
        ));
    }

    let (group_size,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM queue_players WHERE queue_id = $1")
            .bind(queue_id)
            .fetch_one(&mut *tx)
            .await?;
    let leaver_ids: Vec<Uuid> = group_of.iter().map(|(id, _)| *id).collect();
    let remainder = group_size as usize - leaver_ids.len();
    if remainder != 0 && remainder != 2 {
        return Err(ActionError::Court(
            "A pair or the whole group can leave — a group is never left with 1 or 3 players."
                .to_string(),
        ));
    }

    lock_credentials(&mut tx, &leaver_ids).await?;
    let removed_group = remainder == 0;
    if removed_group {
        // Whole group gone: delete + renumber to dense 1..N.
        remove_queue_group(&mut tx, club.id, court_number, queue_id).await?;
    } else {
        // A pair steps out of a 4-group: a pair-group stays, position kept.
        for id in &leaver_ids {
            sqlx::query("DELETE FROM queue_players WHERE queue_id = $1 AND credential_id = $2")
                .bind(queue_id)
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
    }
    tx.commit().await?;
    Ok(removed_group)
}

// ---- walk-in signup / member check-in stations -------------------------------

/// Walk-in station username rule: 3–20 chars of a-z 0-9 _ . - (entered
/// lowercase; the station lowercases before submit anyway).
pub fn valid_kiosk_username(username: &str) -> bool {
    (3..=20).contains(&username.len())
        && username
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-'))
}

/// Why a walk-in username is not available right now (None = available).
/// Taken today = ANY credential row for today (an active pass is in use; a
/// revoked one still owns the (club, username, day) unique slot until
/// tomorrow) OR the username belongs to an active member (permanently
/// reserved). Frees itself after the day because tomorrow is a new valid_date.
pub async fn walkin_unavailable_reason(
    db: &PgPool,
    club: &ClubRow,
    username: &str,
) -> Result<Option<&'static str>, sqlx::Error> {
    if !valid_kiosk_username(username) {
        return Ok(Some("invalid"));
    }
    let (cred_today,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM club_credentials
         WHERE club_id = $1 AND username = $2 AND valid_date = $3",
    )
    .bind(club.id)
    .bind(username)
    .bind(club.today())
    .fetch_one(db)
    .await?;
    if cred_today > 0 {
        return Ok(Some("taken"));
    }
    let (member,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM club_members
         WHERE club_id = $1 AND username = $2 AND status = 'active'",
    )
    .bind(club.id)
    .bind(username)
    .fetch_one(db)
    .await?;
    Ok(if member > 0 { Some("taken") } else { None })
}

/// Why a walk-in signup was refused.
#[derive(Debug)]
pub enum WalkinError {
    /// Same reason codes as the availability check ("invalid" | "taken").
    Unavailable(&'static str),
    Db(sqlx::Error),
}

impl From<sqlx::Error> for WalkinError {
    fn from(e: sqlx::Error) -> Self {
        WalkinError::Db(e)
    }
}

/// Self-serve walk-in signup: claim `username` for today and hand back a fresh
/// memorable password. Runs in a transaction holding the (club, username)
/// advisory lock (lock_username) so it serializes with admin_add_member —
/// without it, the two cross-table check-then-insert paths could both pass
/// their checks and commit a member + same-day walk-in sharing one username.
pub async fn walkin_create(
    db: &PgPool,
    club: &ClubRow,
    username: &str,
) -> Result<String, WalkinError> {
    if !valid_kiosk_username(username) {
        return Err(WalkinError::Unavailable("invalid"));
    }
    let mut tx = db.begin().await?;
    // The ONLY advisory lock this path takes (see lock_username's order note).
    lock_username(&mut tx, club.id, username).await?;
    let member_reserved: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM club_members
         WHERE club_id = $1 AND username = $2 AND status = 'active'",
    )
    .bind(club.id)
    .bind(username)
    .fetch_one(&mut *tx)
    .await?;
    if member_reserved > 0 {
        return Err(WalkinError::Unavailable("taken"));
    }
    let password = generate_password();
    // valid_date is written EXPLICITLY in the club's timezone — the DB
    // server's CURRENT_DATE default is a different clock.
    let inserted = sqlx::query(
        "INSERT INTO club_credentials (club_id, username, password, kind, valid_date)
         VALUES ($1, $2, $3, 'walkin', $4)",
    )
    .bind(club.id)
    .bind(username)
    .bind(&password)
    .bind(club.today())
    .execute(&mut *tx)
    .await;
    match inserted {
        Ok(_) => {
            tx.commit().await?;
            Ok(password)
        }
        // Two concurrent walk-in creates on one username still resolve via the
        // (club, username, valid_date) unique into a friendly "taken".
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
            Err(WalkinError::Unavailable("taken"))
        }
        Err(e) => Err(WalkinError::Db(e)),
    }
}

/// Member check-in result: the member's permanent username + TODAY's password.
#[derive(Debug)]
pub struct CheckinResult {
    pub display_name: Option<String>,
    pub member_ref: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug)]
pub enum CheckinError {
    /// No active member holds this card ID (counts toward the station lockout).
    UnknownMember,
    /// Today's pass exists but was revoked by staff — the desk must resolve it.
    Revoked,
    /// Today's (club, username) slot is held by a credential that is NOT this
    /// member's (a walk-in squatting the member's username today). The desk
    /// must resolve it; the slot frees itself tomorrow.
    UsernameHeld,
    Db(sqlx::Error),
}

impl From<sqlx::Error> for CheckinError {
    fn from(e: sqlx::Error) -> Self {
        CheckinError::Db(e)
    }
}

/// Member check-in: exact card scan/typed member_ref -> find-or-create TODAY's
/// member-kind credential. Same password redisplayed all day; a new one is
/// generated tomorrow simply because tomorrow is a new valid_date row.
pub async fn member_checkin(
    db: &PgPool,
    club: &ClubRow,
    member_ref: &str,
) -> Result<CheckinResult, CheckinError> {
    let member: Option<(Uuid, String, Option<String>, String)> = sqlx::query_as(
        "SELECT id, username, display_name, member_ref FROM club_members
         WHERE club_id = $1 AND member_ref = $2 AND status = 'active'",
    )
    .bind(club.id)
    .bind(member_ref)
    .fetch_optional(db)
    .await?;
    let Some((member_id, username, display_name, member_ref)) = member else {
        return Err(CheckinError::UnknownMember);
    };
    let today = club.today();

    // Find-or-create with one retry: the (club, username, valid_date) unique
    // constraint makes two concurrent check-ins converge on the same row.
    for _ in 0..2 {
        let existing: Option<(String, String)> = sqlx::query_as(
            "SELECT password, status FROM club_credentials
             WHERE club_id = $1 AND member_id = $2 AND valid_date = $3",
        )
        .bind(club.id)
        .bind(member_id)
        .bind(today)
        .fetch_optional(db)
        .await?;
        if let Some((password, status)) = existing {
            if status != "active" {
                return Err(CheckinError::Revoked);
            }
            return Ok(CheckinResult {
                display_name,
                member_ref,
                username,
                password,
            });
        }
        let inserted = sqlx::query(
            "INSERT INTO club_credentials (club_id, username, password, kind, member_id, valid_date)
             VALUES ($1, $2, $3, 'member', $4, $5)",
        )
        .bind(club.id)
        .bind(&username)
        .bind(generate_password())
        .bind(member_id)
        .bind(today)
        .execute(db)
        .await;
        match inserted {
            Ok(_) => continue, // re-select so a concurrent winner's password is returned
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                // Who holds the (club, username, valid_date) slot? A
                // concurrent check-in of the SAME member converges via the
                // re-select above; anything else (a walk-in holding the
                // member's username today) is a distinct friendly conflict —
                // looping would only dead-end in RowNotFound.
                let holder: Option<(Option<Uuid>,)> = sqlx::query_as(
                    "SELECT member_id FROM club_credentials
                     WHERE club_id = $1 AND username = $2 AND valid_date = $3",
                )
                .bind(club.id)
                .bind(&username)
                .bind(today)
                .fetch_optional(db)
                .await?;
                match holder {
                    Some((Some(mid),)) if mid == member_id => continue,
                    Some(_) => return Err(CheckinError::UsernameHeld),
                    None => continue, // blocking row vanished — retry the insert
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    // Second loop iteration always finds the row; reaching here means the row
    // vanished between insert and select twice — give up loudly.
    Err(CheckinError::Db(sqlx::Error::RowNotFound))
}

// ---- timed closures ----------------------------------------------------------

/// Validate a closure window: until must be after from, and from may not sit
/// meaningfully in the past (5 min of slack for clock skew / form dwell time).
pub fn valid_close_window(
    from: DateTime<Utc>,
    until: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), &'static str> {
    if until <= from {
        return Err("The closure must end after it starts.");
    }
    if from < now - chrono::Duration::minutes(5) {
        return Err("The closure can't start in the past.");
    }
    Ok(())
}

/// The DATABASE's current instant — the same clock COURT_CLOSED_SQL compares
/// closure windows against. Closure-boundary watermarks MUST come from this
/// clock, never the app clock: an app clock running ahead of Postgres would
/// broadcast a "reopened" board while the DB still computes closed, then move
/// the watermark past the boundary so no later broadcast ever comes.
pub async fn db_now(db: &PgPool) -> Result<DateTime<Utc>, sqlx::Error> {
    sqlx::query_scalar("SELECT NOW()").fetch_one(db).await
}

/// Clubs whose closure windows crossed a boundary (started or ended) in
/// (since, now] — the engine broadcasts these each tick so boards repaint the
/// moment a court closes or reopens itself. Both instants must come from
/// db_now (see there).
pub async fn closure_boundary_clubs(
    db: &PgPool,
    since: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT DISTINCT club_id FROM club_courts
         WHERE (closed_from  > $1 AND closed_from  <= $2)
            OR (closed_until > $1 AND closed_until <= $2)",
    )
    .bind(since)
    .bind(now)
    .fetch_all(db)
    .await
}

/// One closure-boundary pass, run by the engine each tick with DB-clock
/// watermarks: releases the queue of every court whose closure window STARTED
/// in (since, now] (under the court's advisory lock — the same discipline as
/// every other queue writer), then returns every club with any boundary
/// (start or end) in the range for broadcasting.
///
/// Releasing at the window START (not at admin-close time) means a
/// future-dated closure keeps its queue promotable until the closure actually
/// begins, and no group is left stranded on a session-less closed court —
/// admin_close_court only releases immediately when its window starts at once.
pub async fn closure_boundary_pass(
    db: &PgPool,
    since: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<Vec<Uuid>, sqlx::Error> {
    let started: Vec<(Uuid, i32)> = sqlx::query_as(
        "SELECT club_id, number FROM club_courts
         WHERE closed_from > $1 AND closed_from <= $2",
    )
    .bind(since)
    .bind(now)
    .fetch_all(db)
    .await?;
    for (club_id, court_number) in started {
        let mut tx = db.begin().await?;
        lock_court(&mut tx, club_id, court_number).await?;
        // Re-check under the lock: an admin reopen (or replaced window)
        // between detection and lock must keep the queue.
        let closed: bool = sqlx::query_scalar(&format!(
            "SELECT {COURT_CLOSED_SQL} FROM club_courts WHERE club_id = $1 AND number = $2"
        ))
        .bind(club_id)
        .bind(court_number)
        .fetch_optional(&mut *tx)
        .await?
        .unwrap_or(false);
        if closed {
            sqlx::query("DELETE FROM court_queues WHERE club_id = $1 AND court_number = $2")
                .bind(club_id)
                .bind(court_number)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
    }
    closure_boundary_clubs(db, since, now).await
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

/// How one promote_next call ended.
enum Promotion {
    /// Old session marked done; the queue-head group now holds the court
    /// (after dropping `dropped` unusable groups).
    Promoted { dropped: usize },
    /// Nothing promotable (queue empty after drops, or court closed). The old
    /// session is untouched — the caller decides extend / clear / done.
    NotPromoted,
    /// The fresh-session insert lost to a concurrent writer that slipped the
    /// lock discipline; the caller should back off (next tick re-evaluates).
    Raced,
}

/// The shared queue-promotion step, used by the expiry engine AND leave-court.
/// MUST be called inside a transaction that already holds the court's advisory
/// lock and has the outgoing session row selected FOR UPDATE.
///
/// Walks the queue front-to-back dropping any group with an unusable
/// credential (credential_usable — revoked OR expired day pass), then, if the
/// court is open and a usable head remains: takes the credential advisory
/// locks of `also_lock` (the caller's own credentials, e.g. the leavers) plus
/// the promoted group in ONE sorted batch (court -> sorted creds, the same
/// acyclic order as validate_players), marks `old_session_id` done, and starts
/// the promoted group's fresh full-length session.
async fn promote_next(
    tx: &mut Transaction<'_, Postgres>,
    club_id: Uuid,
    court_number: i32,
    session_minutes: i32,
    closed: bool,
    today: NaiveDate,
    old_session_id: Uuid,
    also_lock: &[Uuid],
) -> Result<Promotion, sqlx::Error> {
    // Walk the queue front-to-back: keep the first fully-usable group,
    // dropping any group containing a revoked or expired credential.
    let mut dropped = 0usize;
    let promoted = loop {
        let head: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM court_queues
             WHERE club_id = $1 AND court_number = $2
             ORDER BY position LIMIT 1",
        )
        .bind(club_id)
        .bind(court_number)
        .fetch_optional(&mut **tx)
        .await?;
        let Some((queue_id,)) = head else { break None };

        let members: Vec<(String, NaiveDate)> = sqlx::query_as(
            "SELECT c.status, c.valid_date FROM queue_players qp
             JOIN club_credentials c ON c.id = qp.credential_id
             WHERE qp.queue_id = $1",
        )
        .bind(queue_id)
        .fetch_all(&mut **tx)
        .await?;
        if members.iter().any(|(status, vd)| !credential_usable(status, *vd, today)) {
            // Drop the whole group and keep looking.
            remove_queue_group(tx, club_id, court_number, queue_id).await?;
            dropped += 1;
            continue;
        }
        break Some(queue_id);
    };

    // A closed court takes no new groups. Its queue is released when the
    // closure BEGINS (immediately by admin_close_court for a window starting
    // now; at the window-start boundary by closure_boundary_pass for a
    // future-dated one), and any stragglers must not land on it.
    let Some(queue_id) = promoted.filter(|_| !closed) else {
        return Ok(Promotion::NotPromoted);
    };

    // Serialize the queue->court move against any kiosk action holding these
    // credentials' locks. One sorted batch covering the caller's credentials
    // AND the promoted group keeps the global lock order acyclic — two sorted
    // batches back-to-back could interleave against validate_players. Without
    // the group's locks, a queued player taking a DIFFERENT free court at the
    // promotion instant could land in two sessions at once.
    let mut to_lock: Vec<Uuid> = sqlx::query_scalar(
        "SELECT credential_id FROM queue_players WHERE queue_id = $1",
    )
    .bind(queue_id)
    .fetch_all(&mut **tx)
    .await?;
    to_lock.extend_from_slice(also_lock);
    lock_credentials(tx, &to_lock).await?;
    sqlx::query("UPDATE court_sessions SET status = 'done' WHERE id = $1")
        .bind(old_session_id)
        .execute(&mut **tx)
        .await?;
    let inserted: Result<Uuid, sqlx::Error> = sqlx::query_scalar(
        "INSERT INTO court_sessions (club_id, court_number, started_at, ends_at)
         VALUES ($1, $2, NOW(), NOW() + make_interval(mins => $3)) RETURNING id",
    )
    .bind(club_id)
    .bind(court_number)
    .bind(session_minutes)
    .fetch_one(&mut **tx)
    .await;
    let new_session: Uuid = match inserted {
        Ok(id) => id,
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => {
            return Ok(Promotion::Raced);
        }
        Err(e) => return Err(e),
    };
    sqlx::query(
        "INSERT INTO session_players (session_id, credential_id)
         SELECT $1, credential_id FROM queue_players WHERE queue_id = $2",
    )
    .bind(new_session)
    .bind(queue_id)
    .execute(&mut **tx)
    .await?;
    remove_queue_group(tx, club_id, court_number, queue_id).await?;
    Ok(Promotion::Promoted { dropped })
}

/// Club fields the engine needs at expiry time.
async fn club_engine_row(
    tx: &mut Transaction<'_, Postgres>,
    club_id: Uuid,
) -> Result<(i32, bool, NaiveDate), sqlx::Error> {
    let (session_minutes, auto_extend, timezone): (i32, bool, String) =
        sqlx::query_as("SELECT session_minutes, auto_extend, timezone FROM clubs WHERE id = $1")
            .bind(club_id)
            .fetch_one(&mut **tx)
            .await?;
    let tz = parse_timezone(&timezone).unwrap_or(time::APP_TZ);
    Ok((session_minutes, auto_extend, time::now().with_timezone(&tz).date_naive()))
}

/// Resolve one expired session under the court's advisory lock. Timer zero →
/// promote queue #1 (dropping revoked/expired groups), else auto-extend, else
/// clear.
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

    let (session_minutes, auto_extend, today) = club_engine_row(&mut tx, club_id).await?;
    let closed: bool = sqlx::query_scalar(&format!(
        "SELECT {COURT_CLOSED_SQL} FROM club_courts WHERE club_id = $1 AND number = $2"
    ))
    .bind(club_id)
    .bind(court_number)
    .fetch_optional(&mut *tx)
    .await?
    // Missing court row (e.g. removed while a session raced onto it): treat
    // as closed so the orphan session drains instead of auto-extending forever.
    .unwrap_or(true);

    match promote_next(
        &mut tx,
        club_id,
        court_number,
        session_minutes,
        closed,
        today,
        session_id,
        &[],
    )
    .await?
    {
        Promotion::Raced => Ok(None),
        Promotion::Promoted { dropped } => {
            tx.commit().await?;
            Ok(Some(EngineOutcome::Promoted { dropped }))
        }
        // Queue empty (after drops) or court closed: auto-extend or clear.
        Promotion::NotPromoted => {
            // A group holding a revoked OR expired credential never
            // auto-extends — same single validity rule as promotion, so a
            // pass that rolled past midnight eventually leaves the court.
            let on_court: Vec<(String, NaiveDate)> = sqlx::query_as(
                "SELECT c.status, c.valid_date FROM session_players sp
                 JOIN club_credentials c ON c.id = sp.credential_id
                 WHERE sp.session_id = $1",
            )
            .bind(session_id)
            .fetch_all(&mut *tx)
            .await?;
            let all_usable =
                on_court.iter().all(|(status, vd)| credential_usable(status, *vd, today));
            if auto_extend && !closed && all_usable {
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
/// Also watches timed-closure windows: a board is nudged the moment one of its
/// courts' windows starts or ends, so "reopens automatically" is actually true.
pub fn spawn_engine(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3));
        // Closure-boundary watermark. Taken from the DATABASE clock (db_now)
        // each tick so the boundary detector and COURT_CLOSED_SQL share one
        // clock — an app/DB clock skew must not strand a "reopened" board.
        // None until the first successful DB clock read.
        let mut last_boundary_check: Option<DateTime<Utc>> = None;
        loop {
            interval.tick().await;
            let mut changed: Vec<Uuid> = Vec::new();
            match engine_tick(&state.db).await {
                Ok(c) => changed = c,
                Err(e) => tracing::warn!(error = %e, "courts engine tick failed"),
            }
            match db_now(&state.db).await {
                Ok(now) => {
                    // First pass after a (re)start looks back a full day: a
                    // window whose start boundary was crossed while the
                    // process was down would otherwise never release its
                    // queue. The pass is idempotent and re-checks the closed
                    // state under the court lock, so over-scanning is safe.
                    let since =
                        last_boundary_check.unwrap_or_else(|| now - chrono::Duration::hours(25));
                    match closure_boundary_pass(&state.db, since, now).await {
                        Ok(clubs) => {
                            last_boundary_check = Some(now);
                            for club_id in clubs {
                                if !changed.contains(&club_id) {
                                    changed.push(club_id);
                                }
                            }
                        }
                        // Keep the old watermark so a failed check is retried,
                        // not skipped.
                        Err(e) => tracing::warn!(error = %e, "closure boundary check failed"),
                    }
                }
                Err(e) => tracing::warn!(error = %e, "db clock read failed"),
            }
            for club_id in changed {
                state.notify_club(club_id);
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

    let courts: Vec<(i32, bool, Option<String>, Option<DateTime<Utc>>)> = sqlx::query_as(&format!(
        "SELECT number, {COURT_CLOSED_SQL}, closed_reason, closed_until FROM club_courts
         WHERE club_id = $1 ORDER BY number"
    ))
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
    for (number, closed, closed_reason, closed_until) in &courts {
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
            // A windowed closure tells the board when the court reopens itself
            // (both the instant and a wall-clock string in the club's tz).
            if let Some(until) = closed_until {
                if *until > now {
                    view["closed_until"] = json!(until.to_rfc3339());
                    view["closed_until_display"] =
                        json!(until.with_timezone(&club.tz()).format("%H:%M").to_string());
                }
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
            "timezone": club.timezone,
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

    // v2: valid_date is written explicitly in the club's timezone — the DB
    // default (server-local CURRENT_DATE) can disagree with the club's "today"
    // around midnight, which is exactly the bug the day-pass model forbids.
    async fn seed_cred(db: &PgPool, club: &ClubRow, username: &str) -> Uuid {
        seed_cred_on(db, club, username, club.today()).await
    }

    async fn seed_cred_on(db: &PgPool, club: &ClubRow, username: &str, day: NaiveDate) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO club_credentials (club_id, username, password, valid_date)
             VALUES ($1, $2, 'pw', $3) RETURNING id",
        )
        .bind(club.id)
        .bind(username)
        .bind(day)
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

    // ================= v2: day passes, stations, unsign, closures =============

    async fn seed_member(db: &PgPool, club: &ClubRow, member_ref: &str, username: &str) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO club_members (club_id, member_ref, username, display_name)
             VALUES ($1, $2, $3, 'Test Member') RETURNING id",
        )
        .bind(club.id)
        .bind(member_ref)
        .bind(username)
        .fetch_one(db)
        .await
        .unwrap()
    }

    fn yesterday(club: &ClubRow) -> NaiveDate {
        club.today() - chrono::Duration::days(1)
    }

    // ---- timezone / validity helper ----

    #[test]
    fn timezone_validation_rejects_garbage() {
        assert!(parse_timezone("America/Los_Angeles").is_some());
        assert!(parse_timezone(" Asia/Tokyo ").is_some(), "surrounding whitespace is trimmed");
        for bad in ["", "America/NotACity", "PST", "UTC+8", "los angeles", "🏸"] {
            assert!(parse_timezone(bad).is_none(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn validity_helper_is_active_and_today_only() {
        let today = chrono::NaiveDate::from_ymd_opt(2026, 8, 11).unwrap();
        let day_before = today - chrono::Duration::days(1);
        assert!(credential_usable("active", today, today));
        assert!(!credential_usable("active", day_before, today), "yesterday's pass is dead");
        assert!(!credential_usable("active", today + chrono::Duration::days(1), today));
        assert!(!credential_usable("revoked", today, today));
    }

    #[sqlx::test]
    async fn club_today_follows_club_timezone(db: PgPool) {
        // Two clubs, timezones ~19h apart: around most of the day their
        // calendar dates differ; they must never both equal the server date by
        // construction (each is derived from its own tz).
        let mk = |slug: &str, tz: &str| {
            let slug = slug.to_string();
            let tz = tz.to_string();
            let db = db.clone();
            async move {
                let club: ClubRow = sqlx::query_as(&format!(
                    "INSERT INTO clubs (slug, name, court_count, timezone) VALUES ($1, 'T', 1, $2)
                     RETURNING {CLUB_COLUMNS}"
                ))
                .bind(slug)
                .bind(&tz)
                .fetch_one(&db)
                .await
                .unwrap();
                club
            }
        };
        let la = mk("club-la", "America/Los_Angeles").await;
        let tokyo = mk("club-tokyo", "Asia/Tokyo").await;
        assert_eq!(la.today(), time::now().with_timezone(&chrono_tz::America::Los_Angeles).date_naive());
        assert_eq!(tokyo.today(), time::now().with_timezone(&chrono_tz::Asia::Tokyo).date_naive());
    }

    // ---- walk-in station ----

    #[sqlx::test]
    async fn walkin_availability_member_reserved_and_freed_next_day(db: PgPool) {
        let club = seed_club(&db).await;
        seed_member(&db, &club, "M-1001", "vikram").await;

        // Charset rule.
        for bad in ["ab", "UPPER", "has space", "way-too-long-for-the-rule", "emoji🏸"] {
            assert_eq!(
                walkin_unavailable_reason(&db, &club, bad).await.unwrap(),
                Some("invalid"),
                "{bad:?}"
            );
        }
        // Member usernames are permanently reserved.
        assert_eq!(
            walkin_unavailable_reason(&db, &club, "vikram").await.unwrap(),
            Some("taken")
        );
        assert!(matches!(
            walkin_create(&db, &club, "vikram").await,
            Err(WalkinError::Unavailable("taken"))
        ));

        // Fresh name: available -> created -> taken for the rest of today.
        assert_eq!(walkin_unavailable_reason(&db, &club, "smash-bro").await.unwrap(), None);
        let password = walkin_create(&db, &club, "smash-bro").await.unwrap();
        assert_eq!(password.split('-').count(), 3, "word-word-NN shape");
        assert_eq!(
            walkin_unavailable_reason(&db, &club, "smash-bro").await.unwrap(),
            Some("taken")
        );
        // The pass is a day pass keyed to the CLUB's today.
        let (kind, valid_date): (String, NaiveDate) = sqlx::query_as(
            "SELECT kind, valid_date FROM club_credentials WHERE club_id = $1 AND username = 'smash-bro'",
        )
        .bind(club.id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(kind, "walkin");
        assert_eq!(valid_date, club.today());

        // Username frees itself after the day (simulated by aging the row).
        sqlx::query("UPDATE club_credentials SET valid_date = $1 WHERE club_id = $2 AND username = 'smash-bro'")
            .bind(yesterday(&club))
            .bind(club.id)
            .execute(&db)
            .await
            .unwrap();
        assert_eq!(walkin_unavailable_reason(&db, &club, "smash-bro").await.unwrap(), None);
        walkin_create(&db, &club, "smash-bro").await.unwrap();
    }

    // ---- member check-in ----

    #[sqlx::test]
    async fn checkin_same_day_idempotent_password_new_next_day(db: PgPool) {
        let club = seed_club(&db).await;
        seed_member(&db, &club, "M-2002", "lin-dan").await;

        let first = member_checkin(&db, &club, "M-2002").await.unwrap();
        assert_eq!(first.username, "lin-dan");
        assert_eq!(first.member_ref, "M-2002");
        // Same password redisplayed on every repeat check-in the same day.
        let again = member_checkin(&db, &club, "M-2002").await.unwrap();
        assert_eq!(again.password, first.password);
        let rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM club_credentials WHERE club_id = $1 AND username = 'lin-dan'",
        )
        .bind(club.id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(rows, 1, "repeat check-ins must not mint extra passes");

        // Next day (inject by aging the row): a NEW pass with a new password.
        sqlx::query("UPDATE club_credentials SET valid_date = $1 WHERE club_id = $2 AND username = 'lin-dan'")
            .bind(yesterday(&club))
            .bind(club.id)
            .execute(&db)
            .await
            .unwrap();
        let next_day = member_checkin(&db, &club, "M-2002").await.unwrap();
        let rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM club_credentials WHERE club_id = $1 AND username = 'lin-dan'",
        )
        .bind(club.id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(rows, 2, "a new day mints a new pass row");
        let today_pass: String = sqlx::query_scalar(
            "SELECT password FROM club_credentials
             WHERE club_id = $1 AND username = 'lin-dan' AND valid_date = $2",
        )
        .bind(club.id)
        .bind(club.today())
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(next_day.password, today_pass);

        // Unknown card + revoked pass are both refused.
        assert!(matches!(
            member_checkin(&db, &club, "M-9999").await,
            Err(CheckinError::UnknownMember)
        ));
        sqlx::query("UPDATE club_credentials SET status = 'revoked' WHERE club_id = $1 AND valid_date = $2")
            .bind(club.id)
            .bind(club.today())
            .execute(&db)
            .await
            .unwrap();
        assert!(matches!(
            member_checkin(&db, &club, "M-2002").await,
            Err(CheckinError::Revoked)
        ));
    }

    // ---- expired passes across take/join/queue + promotion ----

    #[sqlx::test]
    async fn expired_pass_rejected_from_take_join_queue(db: PgPool) {
        let club = seed_club(&db).await;
        seed_cred_on(&db, &club, "stale", yesterday(&club)).await;
        for u in ["a1", "b1", "c1", "d1", "e1"] {
            seed_cred(&db, &club, u).await;
        }

        // take: expired flagged with its own code.
        let errs = validation_errors(
            take_court(&db, &club, 1, &creds(&["stale", "a1"])).await.unwrap_err(),
        );
        assert_eq!(
            errs,
            vec![CredError { username: "stale".into(), code: "expired", court_number: None }]
        );
        // join: court goes half, expired still refused.
        take_court(&db, &club, 1, &creds(&["a1", "b1"])).await.unwrap();
        let errs = validation_errors(
            join_court(&db, &club, 1, &creds(&["stale", "c1"])).await.unwrap_err(),
        );
        assert_eq!(errs[0].code, "expired");
        // queue: court full, expired still refused.
        join_court(&db, &club, 1, &creds(&["c1", "d1"])).await.unwrap();
        let errs = validation_errors(
            queue_court(&db, &club, 1, &creds(&["stale", "e1"])).await.unwrap_err(),
        );
        assert_eq!(errs[0].code, "expired");
    }

    #[sqlx::test]
    async fn engine_drops_expired_group_at_promotion(db: PgPool) {
        let club = seed_club(&db).await;
        let a = seed_cred(&db, &club, "a1").await;
        let b = seed_cred(&db, &club, "b1").await;
        let stale = seed_cred_on(&db, &club, "stale", yesterday(&club)).await;
        let stale2 = seed_cred(&db, &club, "stale2").await;
        let c = seed_cred(&db, &club, "c1").await;
        let d = seed_cred(&db, &club, "d1").await;

        seed_expired_session(&db, &club, 1, &[a, b]).await;
        seed_queue_group(&db, &club, 1, 1, &[stale, stale2]).await; // one expired → drop
        seed_queue_group(&db, &club, 1, 2, &[c, d]).await;

        let outcome = expire_court(&db, club.id, 1).await.unwrap();
        assert_eq!(outcome, Some(EngineOutcome::Promoted { dropped: 1 }));
        let mut on_court = active_session_players(&db, &club, 1).await;
        on_court.sort();
        let mut expected = vec![c, d];
        expected.sort();
        assert_eq!(on_court, expected, "expired group must be dropped, not promoted");
    }

    #[sqlx::test]
    async fn expired_pass_on_court_blocks_auto_extend(db: PgPool) {
        let club = seed_club(&db).await; // auto_extend = true
        let a = seed_cred_on(&db, &club, "a1", yesterday(&club)).await;
        let b = seed_cred(&db, &club, "b1").await;
        let sid = seed_expired_session(&db, &club, 2, &[a, b]).await;

        let outcome = expire_court(&db, club.id, 2).await.unwrap();
        assert_eq!(
            outcome,
            Some(EngineOutcome::Cleared),
            "expired == revoked: the group must not keep the court"
        );
        let status: String = sqlx::query_scalar("SELECT status FROM court_sessions WHERE id = $1")
            .bind(sid)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(status, "done");
    }

    // ---- leave court ----

    #[sqlx::test]
    async fn leave_court_pair_leaves_four_becomes_half(db: PgPool) {
        let club = seed_club(&db).await;
        for u in ["a1", "b1", "c1", "d1"] {
            seed_cred(&db, &club, u).await;
        }
        take_court(&db, &club, 1, &creds(&["a1", "b1", "c1", "d1"])).await.unwrap();

        let out = leave_court(&db, &club, 1, &creds(&["c1", "d1"])).await.unwrap();
        assert_eq!(out, LeaveOutcome { session_ended: false, promoted: false });
        assert_eq!(active_session_players(&db, &club, 1).await.len(), 2, "game continues as half");

        // The freed halves can be re-joined…
        join_court(&db, &club, 1, &creds(&["c1", "d1"])).await.unwrap();
        // …and 1-or-3 can never remain: a lone leaver is refused outright.
        assert!(matches!(
            leave_court(&db, &club, 1, &creds(&["a1"])).await,
            Err(ActionError::Court(_))
        ));
    }

    #[sqlx::test]
    async fn leave_court_whole_group_promotes_queue_immediately(db: PgPool) {
        let club = seed_club(&db).await;
        let mut ids = Vec::new();
        for u in ["a1", "b1", "c1", "d1", "e1", "f1", "g1", "h1"] {
            ids.push(seed_cred(&db, &club, u).await);
        }
        take_court(&db, &club, 1, &creds(&["a1", "b1", "c1", "d1"])).await.unwrap();
        queue_court(&db, &club, 1, &creds(&["e1", "f1"])).await.unwrap();
        queue_court(&db, &club, 1, &creds(&["g1", "h1"])).await.unwrap();

        let out = leave_court(&db, &club, 1, &creds(&["a1", "b1", "c1", "d1"])).await.unwrap();
        assert_eq!(out, LeaveOutcome { session_ended: true, promoted: true });

        // Queue head (e1,f1) is on the court with a FULL fresh timer.
        let mut on_court = active_session_players(&db, &club, 1).await;
        on_court.sort();
        let mut expected = vec![ids[4], ids[5]];
        expected.sort();
        assert_eq!(on_court, expected, "queue head must hold the court immediately");
        let positions: Vec<(i32,)> = sqlx::query_as(
            "SELECT position FROM court_queues WHERE club_id = $1 ORDER BY position",
        )
        .bind(club.id)
        .fetch_all(&db)
        .await
        .unwrap();
        assert_eq!(positions, vec![(1,)], "remaining group renumbered to the head");

        // Leavers' creds are free again immediately: the promoted half court
        // can be joined by two of them on the spot.
        join_court(&db, &club, 1, &creds(&["a1", "b1"])).await.unwrap();
    }

    #[sqlx::test]
    async fn leave_court_pair_ends_pair_session_and_flags_outsiders(db: PgPool) {
        let club = seed_club(&db).await;
        for u in ["a1", "b1", "x1", "y1"] {
            seed_cred(&db, &club, u).await;
        }
        take_court(&db, &club, 2, &creds(&["a1", "b1"])).await.unwrap();

        // Someone not on the court cannot "leave" it.
        let errs = validation_errors(
            leave_court(&db, &club, 2, &creds(&["a1", "x1"])).await.unwrap_err(),
        );
        assert_eq!(
            errs,
            vec![CredError { username: "x1".into(), code: "not_on_court", court_number: Some(2) }]
        );

        // The whole pair leaving ends the session; queue empty → court free.
        let out = leave_court(&db, &club, 2, &creds(&["a1", "b1"])).await.unwrap();
        assert_eq!(out, LeaveOutcome { session_ended: true, promoted: false });
        assert!(active_session_players(&db, &club, 2).await.is_empty());
        // Court is genuinely available again.
        take_court(&db, &club, 2, &creds(&["x1", "y1"])).await.unwrap();
    }

    #[sqlx::test]
    async fn leave_court_refused_once_timer_expired(db: PgPool) {
        let club = seed_club(&db).await;
        let a = seed_cred(&db, &club, "a1").await;
        let b = seed_cred(&db, &club, "b1").await;
        seed_expired_session(&db, &club, 1, &[a, b]).await;

        match leave_court(&db, &club, 1, &creds(&["a1", "b1"])).await {
            Err(ActionError::Court(msg)) => assert!(msg.contains("finishing up"), "{msg}"),
            other => panic!("leave on an expired session must defer to the engine, got {other:?}"),
        }
    }

    // ---- leave queue ----

    #[sqlx::test]
    async fn leave_queue_removes_group_and_renumbers(db: PgPool) {
        let club = seed_club(&db).await;
        for u in ["a1", "b1", "c1", "d1", "e1", "f1", "g1", "h1", "i1", "j1"] {
            seed_cred(&db, &club, u).await;
        }
        take_court(&db, &club, 1, &creds(&["a1", "b1", "c1", "d1"])).await.unwrap();
        queue_court(&db, &club, 1, &creds(&["e1", "f1"])).await.unwrap(); // pos 1
        queue_court(&db, &club, 1, &creds(&["g1", "h1"])).await.unwrap(); // pos 2
        queue_court(&db, &club, 1, &creds(&["i1", "j1"])).await.unwrap(); // pos 3

        // Middle group leaves whole → dense renumber 1..2.
        assert!(leave_queue(&db, &club, 1, &creds(&["g1", "h1"])).await.unwrap());
        let rows: Vec<(i32, String)> = sqlx::query_as(
            "SELECT q.position, c.username FROM court_queues q
             JOIN queue_players qp ON qp.queue_id = q.id
             JOIN club_credentials c ON c.id = qp.credential_id
             WHERE q.club_id = $1 ORDER BY q.position, c.username",
        )
        .bind(club.id)
        .fetch_all(&db)
        .await
        .unwrap();
        assert_eq!(
            rows,
            vec![
                (1, "e1".into()),
                (1, "f1".into()),
                (2, "i1".into()),
                (2, "j1".into())
            ]
        );

        // Leavers spanning two groups are refused.
        match leave_queue(&db, &club, 1, &creds(&["e1", "i1"])).await {
            Err(ActionError::Court(msg)) => assert!(msg.contains("same queue group"), "{msg}"),
            other => panic!("cross-group leave must be refused, got {other:?}"),
        }
        // Someone not queued gets a per-field error.
        let errs = validation_errors(
            leave_queue(&db, &club, 1, &creds(&["a1", "e1"])).await.unwrap_err(),
        );
        assert_eq!(
            errs,
            vec![CredError { username: "a1".into(), code: "not_in_queue", court_number: Some(1) }]
        );
    }

    #[sqlx::test]
    async fn leave_queue_pair_leaves_four_group_pair_stays(db: PgPool) {
        let club = seed_club(&db).await;
        for u in ["a1", "b1", "c1", "d1", "e1", "f1", "g1", "h1"] {
            seed_cred(&db, &club, u).await;
        }
        take_court(&db, &club, 1, &creds(&["a1", "b1", "c1", "d1"])).await.unwrap();
        queue_court(&db, &club, 1, &creds(&["e1", "f1", "g1", "h1"])).await.unwrap();

        // A pair steps out of the 4-group: a pair-group remains at position 1.
        assert!(!leave_queue(&db, &club, 1, &creds(&["g1", "h1"])).await.unwrap());
        let rows: Vec<(i32, String)> = sqlx::query_as(
            "SELECT q.position, c.username FROM court_queues q
             JOIN queue_players qp ON qp.queue_id = q.id
             JOIN club_credentials c ON c.id = qp.credential_id
             WHERE q.club_id = $1 ORDER BY q.position, c.username",
        )
        .bind(club.id)
        .fetch_all(&db)
        .await
        .unwrap();
        assert_eq!(rows, vec![(1, "e1".into()), (1, "f1".into())]);
        // The leavers are free to queue again (fresh group at position 2).
        assert_eq!(queue_court(&db, &club, 1, &creds(&["g1", "h1"])).await.unwrap(), 2);
    }

    // ---- timed closures ----

    #[test]
    fn close_window_validation() {
        let now = time::now();
        let in_1h = now + chrono::Duration::hours(1);
        let in_2h = now + chrono::Duration::hours(2);
        assert!(valid_close_window(now, in_1h, now).is_ok());
        assert!(valid_close_window(in_1h, in_2h, now).is_ok(), "future windows are fine");
        // until must be strictly after from.
        assert!(valid_close_window(in_1h, in_1h, now).is_err());
        assert!(valid_close_window(in_2h, in_1h, now).is_err());
        // from more than 5 minutes in the past is rejected…
        assert!(valid_close_window(now - chrono::Duration::minutes(6), in_1h, now).is_err());
        // …but form-dwell slack is tolerated.
        assert!(valid_close_window(now - chrono::Duration::minutes(4), in_1h, now).is_ok());
    }

    #[sqlx::test]
    async fn closure_window_computes_closed_state_and_reopens(db: PgPool) {
        let club = seed_club(&db).await;
        for u in ["a1", "b1"] {
            seed_cred(&db, &club, u).await;
        }
        // Window currently in progress → closed.
        sqlx::query(
            "UPDATE club_courts
             SET closed_from = NOW() - INTERVAL '10 minutes',
                 closed_until = NOW() + INTERVAL '50 minutes',
                 closed_reason = 'mat repair'
             WHERE club_id = $1 AND number = 3",
        )
        .bind(club.id)
        .execute(&db)
        .await
        .unwrap();
        assert!(matches!(
            take_court(&db, &club, 3, &creds(&["a1", "b1"])).await,
            Err(ActionError::Court(_))
        ));
        let board = board_snapshot(&db, &club).await.unwrap();
        let court3 = &board["courts"][2];
        assert_eq!(court3["status"], "closed");
        assert_eq!(court3["closed_reason"], "mat repair");
        assert!(court3["closed_until"].is_string(), "board carries the reopen instant");
        assert!(court3["closed_until_display"].is_string());

        // Window fully in the past → computed OPEN with no admin action.
        sqlx::query(
            "UPDATE club_courts
             SET closed_from = NOW() - INTERVAL '2 hours',
                 closed_until = NOW() - INTERVAL '1 hour'
             WHERE club_id = $1 AND number = 3",
        )
        .bind(club.id)
        .execute(&db)
        .await
        .unwrap();
        take_court(&db, &club, 3, &creds(&["a1", "b1"])).await.unwrap();
        let board = board_snapshot(&db, &club).await.unwrap();
        assert_eq!(board["courts"][2]["status"], "half", "expired window reopens by itself");

        // Boundary detection: both edges of a window inside (since, now].
        let clubs = closure_boundary_clubs(
            &db,
            time::now() - chrono::Duration::hours(3),
            time::now(),
        )
        .await
        .unwrap();
        assert_eq!(clubs, vec![club.id]);
        let clubs = closure_boundary_clubs(
            &db,
            time::now() - chrono::Duration::minutes(1),
            time::now(),
        )
        .await
        .unwrap();
        assert!(clubs.is_empty(), "no boundary crossed in the last minute");
    }

    #[sqlx::test]
    async fn engine_does_not_promote_onto_window_closed_court(db: PgPool) {
        let club = seed_club(&db).await; // auto_extend = true
        let a = seed_cred(&db, &club, "a1").await;
        let b = seed_cred(&db, &club, "b1").await;
        let c = seed_cred(&db, &club, "c1").await;
        let d = seed_cred(&db, &club, "d1").await;
        seed_expired_session(&db, &club, 1, &[a, b]).await;
        seed_queue_group(&db, &club, 1, 1, &[c, d]).await;
        sqlx::query(
            "UPDATE club_courts
             SET closed_from = NOW() - INTERVAL '1 minute',
                 closed_until = NOW() + INTERVAL '1 hour'
             WHERE club_id = $1 AND number = 1",
        )
        .bind(club.id)
        .execute(&db)
        .await
        .unwrap();

        // Window-closed behaves exactly like bool-closed: session drains, no
        // promotion, no auto-extend.
        let outcome = expire_court(&db, club.id, 1).await.unwrap();
        assert_eq!(outcome, Some(EngineOutcome::Cleared));
        assert!(active_session_players(&db, &club, 1).await.is_empty());
    }

    async fn queue_group_count(db: &PgPool, club: &ClubRow) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM court_queues WHERE club_id = $1")
            .bind(club.id)
            .fetch_one(db)
            .await
            .unwrap()
    }

    #[sqlx::test]
    async fn leave_whole_group_on_window_closed_court_does_not_promote(db: PgPool) {
        let club = seed_club(&db).await;
        for u in ["a1", "b1", "c1", "d1", "e1", "f1"] {
            seed_cred(&db, &club, u).await;
        }
        take_court(&db, &club, 1, &creds(&["a1", "b1", "c1", "d1"])).await.unwrap();
        queue_court(&db, &club, 1, &creds(&["e1", "f1"])).await.unwrap();
        // A closure window starts mid-session.
        sqlx::query(
            "UPDATE club_courts
             SET closed_from = NOW() - INTERVAL '1 minute',
                 closed_until = NOW() + INTERVAL '1 hour'
             WHERE club_id = $1 AND number = 1",
        )
        .bind(club.id)
        .execute(&db)
        .await
        .unwrap();

        // The whole group signs off: session ends, but NOBODY is promoted
        // onto the closed court (same rule as the engine path).
        let out = leave_court(&db, &club, 1, &creds(&["a1", "b1", "c1", "d1"])).await.unwrap();
        assert_eq!(out, LeaveOutcome { session_ended: true, promoted: false });
        assert!(active_session_players(&db, &club, 1).await.is_empty());

        // leave_court itself never touches the queue — releasing it at the
        // closure's start is the boundary pass's job (next tick).
        assert_eq!(queue_group_count(&db, &club).await, 1);
        let now = db_now(&db).await.unwrap();
        let clubs = closure_boundary_pass(&db, now - chrono::Duration::minutes(5), now)
            .await
            .unwrap();
        assert_eq!(clubs, vec![club.id]);
        assert_eq!(queue_group_count(&db, &club).await, 0, "boundary pass releases the queue");
    }

    #[sqlx::test]
    async fn checkin_friendly_conflict_when_walkin_holds_username(db: PgPool) {
        let club = seed_club(&db).await;
        seed_member(&db, &club, "M-3003", "sharedname").await;
        // A walk-in row squatting the member's username TODAY (inserted
        // directly — the shape the pre-lock race could commit).
        sqlx::query(
            "INSERT INTO club_credentials (club_id, username, password, kind, valid_date)
             VALUES ($1, 'sharedname', 'pw', 'walkin', $2)",
        )
        .bind(club.id)
        .bind(club.today())
        .execute(&db)
        .await
        .unwrap();

        match member_checkin(&db, &club, "M-3003").await {
            Err(CheckinError::UsernameHeld) => {}
            other => panic!("expected the friendly walk-in-holds-username conflict, got {other:?}"),
        }
        // No member credential was minted alongside the squatter.
        let rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM club_credentials WHERE club_id = $1 AND username = 'sharedname'",
        )
        .bind(club.id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(rows, 1);
    }

    #[sqlx::test]
    async fn expired_pass_can_still_leave_court_and_queue(db: PgPool) {
        let club = seed_club(&db).await;
        let mut ids = Vec::new();
        for u in ["a1", "b1", "c1", "d1", "g1", "h1"] {
            ids.push(seed_cred(&db, &club, u).await);
        }
        take_court(&db, &club, 1, &creds(&["a1", "b1", "c1", "d1"])).await.unwrap();
        queue_court(&db, &club, 1, &creds(&["g1", "h1"])).await.unwrap();

        // Midnight passes: every pass rolls out of validity while the players
        // are still physically placed. Signing off must always work.
        let age = |id: Uuid| {
            let db = db.clone();
            let day = yesterday(&club);
            async move {
                sqlx::query("UPDATE club_credentials SET valid_date = $1 WHERE id = $2")
                    .bind(day)
                    .bind(id)
                    .execute(&db)
                    .await
                    .unwrap();
            }
        };
        for id in &ids {
            age(*id).await;
        }

        // Expired queue group can leave the queue…
        assert!(leave_queue(&db, &club, 1, &creds(&["g1", "h1"])).await.unwrap());
        assert_eq!(queue_group_count(&db, &club).await, 0);
        // …and the expired on-court group can sign off (queue now empty, so
        // nothing is promoted).
        let out = leave_court(&db, &club, 1, &creds(&["a1", "b1", "c1", "d1"])).await.unwrap();
        assert_eq!(out, LeaveOutcome { session_ended: true, promoted: false });
        assert!(active_session_players(&db, &club, 1).await.is_empty());

        // Play paths still refuse the expired passes (expired == revoked).
        let errs = validation_errors(
            take_court(&db, &club, 2, &creds(&["a1", "b1"])).await.unwrap_err(),
        );
        assert!(errs.iter().all(|e| e.code == "expired"));
    }

    #[sqlx::test]
    async fn closure_start_boundary_releases_queue(db: PgPool) {
        let club = seed_club(&db).await;
        for u in ["a1", "b1", "c1", "d1", "e1", "f1"] {
            seed_cred(&db, &club, u).await;
        }
        take_court(&db, &club, 1, &creds(&["a1", "b1", "c1", "d1"])).await.unwrap();
        queue_court(&db, &club, 1, &creds(&["e1", "f1"])).await.unwrap();
        // A (previously future-dated) closure window whose start has just
        // arrived — written directly, the way admin_close_court stores it.
        sqlx::query(
            "UPDATE club_courts
             SET closed_from = NOW(), closed_until = NOW() + INTERVAL '1 hour'
             WHERE club_id = $1 AND number = 1",
        )
        .bind(club.id)
        .execute(&db)
        .await
        .unwrap();

        let now = db_now(&db).await.unwrap();
        let clubs = closure_boundary_pass(&db, now - chrono::Duration::minutes(1), now)
            .await
            .unwrap();
        assert_eq!(clubs, vec![club.id], "start boundary must be detected");
        assert_eq!(queue_group_count(&db, &club).await, 0, "queue released at window start");
        // The running session plays out — closure never evicts mid-game.
        assert_eq!(active_session_players(&db, &club, 1).await.len(), 4);

        // A pass over the same range is idempotent.
        let clubs = closure_boundary_pass(&db, now - chrono::Duration::minutes(1), now)
            .await
            .unwrap();
        assert_eq!(clubs, vec![club.id]);
        assert_eq!(queue_group_count(&db, &club).await, 0);
    }
}
