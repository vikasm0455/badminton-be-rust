//! Scheduled background work (PRD §13). One 60-second tick loop drives all
//! time-of-day jobs, comparing against America/Los_Angeles wall-clock so DST is
//! handled for free. Each daily job is guarded by a "last run date" stamp in
//! app_config, which doubles as startup recovery: a job whose time has already
//! passed today (and hasn't run) fires on the next tick after boot.

use chrono::{NaiveDate, NaiveTime};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::error::ApiError;
use crate::state::{AppState, LiveEvent};
use crate::{notify, time};

pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        // Immediate recovery pass for anything missed while the server was down.
        startup_recovery(&state).await;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            if let Err(e) = tick(&state).await {
                tracing::warn!(error = %e, "scheduler tick error");
            }
        }
    });
}

async fn startup_recovery(state: &AppState) {
    // Missed midnight cleanup: drop any credentials from previous days.
    match clear_credentials_before(state, time::today()).await {
        Ok(n) if n > 0 => tracing::info!(removed = n, "startup: cleared stale credentials"),
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "startup credential cleanup failed"),
    }
    // Missed auto-poll handled by the normal tick guard below.
}

async fn tick(state: &AppState) -> Result<(), ApiError> {
    let today = time::today();
    let now_t = time::local_time_now();

    // ---- per-minute realtime jobs -----------------------------------------
    timer_and_prestart(state).await?;

    // ---- daily time-of-day jobs (guarded once/day) ------------------------
    // Per-group auto-poll + final reminder.
    let auto_groups: Vec<(Uuid, NaiveTime, NaiveTime, String)> = sqlx::query_as(
        "SELECT id, auto_poll_time, final_reminder_time, auto_poll_note
         FROM groups WHERE auto_poll_enabled = true",
    )
    .fetch_all(&state.db)
    .await?;
    for (gid, poll_t, reminder_t, note) in auto_groups {
        if due(state, &format!("auto_poll_{gid}"), poll_t, now_t, today).await {
            let created = ensure_today_poll(state, gid, poll_t, &note).await?;
            stamp(state, &format!("auto_poll_{gid}"), today).await;
            if created {
                tracing::info!(group = %gid, "auto-poll created");
            }
        }
        // Final reminder: only if fewer than 2 Yes votes (PRD §21 Q4). Stamped
        // only on success so a transient DB error retries next tick.
        if due(state, &format!("final_reminder_{gid}"), reminder_t, now_t, today).await {
            match final_reminder(state, gid, today).await {
                Ok(()) => stamp(state, &format!("final_reminder_{gid}"), today).await,
                Err(e) => tracing::warn!(error = %e, group = %gid, "final reminder failed; will retry"),
            }
        }
    }

    // Credential midnight cleanup (23:59).
    if due(state, "cred_cleanup", NaiveTime::from_hms_opt(23, 59, 0).unwrap(), now_t, today).await {
        // Which groups had logins today? (Fetched before the delete wipes shares.)
        let groups: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT DISTINCT s.group_id FROM credential_shares s
             JOIN court_credentials c ON c.id = s.credential_id WHERE c.game_date = $1",
        )
        .bind(today)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();
        let removed = clear_credentials_for(state, today).await?;
        notify::credentials_cleared(state, groups.into_iter().map(|g| g.0).collect());
        state.broadcast(LiveEvent::CredentialsChanged);
        stamp(state, "cred_cleanup", today).await;
        tracing::info!(removed, "midnight credential cleanup");
    }

    // Security event pruning (02:00, >90 days).
    if due(state, "security_prune", NaiveTime::from_hms_opt(2, 0, 0).unwrap(), now_t, today).await {
        let _ = sqlx::query("DELETE FROM security_events WHERE created_at < NOW() - INTERVAL '90 days'")
            .execute(&state.db)
            .await;
        stamp(state, "security_prune", today).await;
    }

    // Stale push subscription cleanup (03:00, >30 days no success).
    if due(state, "push_cleanup", NaiveTime::from_hms_opt(3, 0, 0).unwrap(), now_t, today).await {
        let _ = sqlx::query(
            "UPDATE push_subscriptions SET active = false
             WHERE active = true AND last_success_at IS NOT NULL
               AND last_success_at < NOW() - INTERVAL '30 days'",
        )
        .execute(&state.db)
        .await;
        stamp(state, "push_cleanup", today).await;
    }

    Ok(())
}

// ---- timer + pre-start notifications ---------------------------------------

#[derive(sqlx::FromRow)]
struct TimerRow {
    id: Uuid,
    group_id: Uuid,
    court_number: i16,
    start_at: chrono::DateTime<chrono::Utc>,
    expiry_at: chrono::DateTime<chrono::Utc>,
    notification_sent_flags: Value,
}

async fn timer_and_prestart(state: &AppState) -> Result<(), ApiError> {
    let now = time::now();
    let rows: Vec<TimerRow> = sqlx::query_as(
        "SELECT id, group_id, court_number, start_at, expiry_at, notification_sent_flags
         FROM court_reservations
         WHERE status = 'active' AND game_date = $1 AND group_id IS NOT NULL",
    )
    .bind(time::today())
    .fetch_all(&state.db)
    .await?;

    for r in rows {
        let mut flags = r.notification_sent_flags.as_object().cloned().unwrap_or_default();
        let mut changed = false;
        let sent = |flags: &serde_json::Map<String, Value>, key: &str| {
            flags.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
        };

        if r.start_at > now {
            // Pre-start: within 5 minutes of starting.
            let to_start = (r.start_at - now).num_seconds();
            if to_start <= 5 * 60 && !sent(&flags, "prestart") {
                notify::prestart(state, r.group_id, r.court_number);
                flags.insert("prestart".into(), json!(true));
                changed = true;
            }
        } else {
            let remaining = (r.expiry_at - now).num_seconds();
            for t in [15i64, 10, 5] {
                if remaining <= t * 60 && remaining > 0 && !sent(&flags, &t.to_string()) {
                    notify::timer_threshold(state, r.group_id, r.court_number, t as i32);
                    flags.insert(t.to_string(), json!(true));
                    changed = true;
                }
            }
            if remaining <= 0 && !sent(&flags, "0") {
                notify::timer_threshold(state, r.group_id, r.court_number, 0);
                flags.insert("0".into(), json!(true));
                changed = true;
                state.broadcast(LiveEvent::ReservationsChanged);
            }
        }

        if changed {
            sqlx::query("UPDATE court_reservations SET notification_sent_flags = $1 WHERE id = $2")
                .bind(Value::Object(flags))
                .bind(r.id)
                .execute(&state.db)
                .await?;
        }
    }
    Ok(())
}

// ---- poll helpers ----------------------------------------------------------

/// Create today's poll for a group if none exists. Returns true if created.
pub async fn ensure_today_poll(
    state: &AppState,
    group_id: Uuid,
    proposed_time: NaiveTime,
    note: &str,
) -> Result<bool, ApiError> {
    let today = time::today();
    let exists: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM polls WHERE game_date = $1 AND group_id = $2")
            .bind(today)
            .bind(group_id)
            .fetch_optional(&state.db)
            .await?;
    if exists.is_some() {
        return Ok(false);
    }

    // Attribute to the group's earliest admin.
    let creator: Option<(Uuid,)> = sqlx::query_as(
        "SELECT user_id FROM group_members
         WHERE group_id = $1 AND role = 'admin' ORDER BY joined_at ASC LIMIT 1",
    )
    .bind(group_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((creator_id,)) = creator else {
        tracing::warn!(group = %group_id, "auto-poll: group has no admin — skipping");
        return Ok(false);
    };
    let note_opt = if note.trim().is_empty() { None } else { Some(note.trim().to_string()) };

    let insert: Result<(Uuid,), sqlx::Error> = sqlx::query_as(
        "INSERT INTO polls (created_by, game_date, proposed_time, note, auto_created, group_id)
         VALUES ($1, $2, $3, $4, true, $5) RETURNING id",
    )
    .bind(creator_id)
    .bind(today)
    .bind(proposed_time)
    .bind(note_opt)
    .bind(group_id)
    .fetch_one(&state.db)
    .await;
    match insert {
        Ok((poll_id,)) => {
            state.broadcast(LiveEvent::PollChanged { poll_id });
            notify::poll_created(
                state,
                group_id,
                None,
                "RallyUp",
                &proposed_time.format("%H:%M").to_string(),
                true,
            );
            Ok(true)
        }
        // Lost the race against a manual poll — that's fine.
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => Ok(false),
        Err(e) => Err(ApiError::Db(e)),
    }
}

async fn final_reminder(state: &AppState, group_id: Uuid, today: NaiveDate) -> Result<(), ApiError> {
    let row: Option<(Uuid, i64)> = sqlx::query_as(
        "SELECT p.id, (SELECT COUNT(*) FROM poll_votes v WHERE v.poll_id = p.id AND v.vote = 'yes')
         FROM polls p WHERE p.game_date = $1 AND p.group_id = $2",
    )
    .bind(today)
    .bind(group_id)
    .fetch_optional(&state.db)
    .await?;
    if let Some((_id, yes)) = row {
        if yes < 2 {
            notify::final_reminder(state, group_id, yes);
        }
    }
    Ok(())
}

// ---- credential cleanup ----------------------------------------------------

/// Delete a specific date's credentials and their screenshot files.
pub async fn clear_credentials_for(state: &AppState, date: NaiveDate) -> Result<u64, ApiError> {
    delete_credentials(state, "game_date = $1", date).await
}

/// Delete credentials strictly before `date` (missed-cleanup recovery).
pub async fn clear_credentials_before(state: &AppState, date: NaiveDate) -> Result<u64, ApiError> {
    delete_credentials(state, "game_date < $1", date).await
}

async fn delete_credentials(state: &AppState, predicate: &str, date: NaiveDate) -> Result<u64, ApiError> {
    let paths: Vec<(Option<String>,)> = sqlx::query_as(&format!(
        "SELECT screenshot_path FROM court_credentials WHERE {predicate}"
    ))
    .bind(date)
    .fetch_all(&state.db)
    .await?;
    for (p,) in &paths {
        if let Some(p) = p {
            let _ = tokio::fs::remove_file(p).await;
        }
    }
    let res = sqlx::query(&format!("DELETE FROM court_credentials WHERE {predicate}"))
        .bind(date)
        .execute(&state.db)
        .await?;
    // Best-effort: remove the now-empty date directory.
    let dir = format!("{}/creds/{}", state.config.uploads_path.trim_end_matches('/'), date);
    let _ = tokio::fs::remove_dir_all(dir).await;
    Ok(res.rows_affected())
}

// ---- config + guards -------------------------------------------------------

async fn read_cfg(state: &AppState, key: &str, default: &str) -> String {
    sqlx::query_as::<_, (String,)>("SELECT value FROM app_config WHERE key = $1")
        .bind(key)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .map(|r| r.0)
        .unwrap_or_else(|| default.to_string())
}

/// A daily job is due if the local time has passed its trigger and it hasn't
/// already run today.
async fn due(state: &AppState, key: &str, at: NaiveTime, now: NaiveTime, today: NaiveDate) -> bool {
    if now < at {
        return false;
    }
    let last = read_cfg(state, &format!("job_last_{key}"), "").await;
    let last_date = chrono::DateTime::parse_from_rfc3339(&last)
        .ok()
        .map(|dt| dt.with_timezone(&time::APP_TZ).date_naive());
    last_date != Some(today)
}

async fn stamp(state: &AppState, key: &str, _today: NaiveDate) {
    let now = time::now().to_rfc3339();
    let _ = sqlx::query(
        "INSERT INTO app_config (key, value, updated_at) VALUES ($1, $2, NOW())
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
    )
    .bind(format!("job_last_{key}"))
    .bind(now)
    .execute(&state.db)
    .await;
}
