//! High-level notification triggers (PRD §8.3 text + §8.4 batching). Wraps the
//! low-level `push` fan-out with the exact copy and category routing. All
//! gameplay notifications are scoped to the GROUP they happened in.

use redis::AsyncCommands;
use uuid::Uuid;

use crate::push::{PushPayload, notify_admins, notify_group, notify_groups, notify_user};
use crate::state::AppState;

/// notif_prefs categories (opt-out: absent key = enabled).
pub mod cat {
    pub const POLLS: &str = "polls";
    pub const VOTES: &str = "votes";
    pub const CREDENTIALS: &str = "credentials";
    pub const RESERVATIONS: &str = "reservations";
    pub const TIMERS: &str = "timers";
    #[allow(dead_code)]
    pub const ADMIN: &str = "admin";
    pub const ACCOUNT: &str = "account";
}

pub fn poll_created(state: &AppState, group_id: Uuid, creator: Option<Uuid>, by_name: &str, time: &str, auto: bool) {
    let payload = if auto {
        PushPayload::new(
            "🏸 Today's badminton poll is live",
            "Vote now!",
            "/home",
            "poll",
        )
    } else {
        PushPayload::new(
            "🏸 New poll for today",
            format!("{by_name} created a poll @ {time} — vote now!"),
            "/home",
            "poll",
        )
    };
    notify_group(state, group_id, payload, creator, cat::POLLS);
}

/// A login was posted and shared with these groups.
pub fn credential_posted(state: &AppState, group_ids: Vec<Uuid>, poster: Uuid, by_name: &str) {
    notify_groups(
        state,
        group_ids,
        PushPayload::new(
            "🔑 New court login posted",
            format!("{by_name} posted today's court login — tap to view"),
            "/creds",
            "creds",
        ),
        Some(poster),
        cat::CREDENTIALS,
    );
}

pub fn reservation_logged(
    state: &AppState,
    group_id: Uuid,
    actor: Uuid,
    by_name: &str,
    court: i16,
    minutes: i16,
    future_time: Option<String>,
) {
    let payload = match future_time {
        Some(t) => PushPayload::new(
            "🏸 Court queued",
            format!("{by_name} queued Court {court} starting at {t}"),
            "/courts",
            "court",
        ),
        None => PushPayload::new(
            "🏸 Court booked",
            format!("{by_name} booked Court {court} — {minutes} min on the clock!"),
            "/courts",
            "court",
        ),
    };
    notify_group(state, group_id, payload, Some(actor), cat::RESERVATIONS);
}

pub fn reservation_complete(state: &AppState, group_id: Uuid, actor: Uuid, court: i16, by_name: &str) {
    notify_group(
        state,
        group_id,
        PushPayload::new(
            "✅ Court complete",
            format!("Court {court} marked complete by {by_name}"),
            "/courts",
            "court",
        ),
        Some(actor),
        cat::RESERVATIONS,
    );
}

/// Timer threshold notifications are never batched (time-critical, PRD §8.4).
pub fn timer_threshold(state: &AppState, group_id: Uuid, court: i16, threshold: i32) {
    let (title, body) = match threshold {
        15 => ("⏳ 15 minutes left", format!("Court {court} has 15 min left — time to re-book!")),
        10 => ("⏳ 10 minutes left", format!("Court {court} — 10 minutes left")),
        5 => ("🔴 5 minutes left", format!("Court {court} expires in 5 minutes!")),
        0 => ("🏸 Session ended", format!("Court {court} session has ended")),
        _ => ("⏳ Court timer", format!("Court {court} timer update")),
    };
    notify_group(
        state,
        group_id,
        PushPayload::new(title, body, "/courts", format!("court-{court}-timer")),
        None,
        cat::TIMERS,
    );
}

pub fn prestart(state: &AppState, group_id: Uuid, court: i16) {
    notify_group(
        state,
        group_id,
        PushPayload::new(
            "⏰ Court starts in 5 minutes",
            format!("Court {court} starts in 5 minutes — head over!"),
            "/courts",
            format!("court-{court}-prestart"),
        ),
        None,
        cat::TIMERS,
    );
}

/// Day-of nudge when a poll is still short on Yes votes (PRD §21 Q4).
pub fn final_reminder(state: &AppState, group_id: Uuid, yes_count: i64) {
    notify_group(
        state,
        group_id,
        PushPayload::new(
            "🏸 Playing tonight?",
            format!("Only {yes_count} Yes so far — vote so the group can plan!"),
            "/home",
            "poll-reminder",
        ),
        None,
        cat::POLLS,
    );
}

/// Nightly clear notice, sent to each group that had logins shared today.
pub fn credentials_cleared(state: &AppState, group_ids: Vec<Uuid>) {
    notify_groups(
        state,
        group_ids,
        PushPayload::new(
            "🌙 Credentials cleared",
            "Today's credentials cleared. See you tomorrow!",
            "/creds",
            "creds-cleared",
        ),
        None,
        cat::CREDENTIALS,
    );
}

/// Site-operator alert (e.g. an account got locked out).
pub fn operator_alert(state: &AppState, text: &str) {
    notify_admins(
        state,
        PushPayload::new("⚠️ RallyUp alert", text.to_string(), "/admin/security", "operator"),
    );
}

// LEGACY-SINGLE-TENANT: member_approved/member_rejected serve the dead
// admin-approval flow — delete with admin.rs approve/reject.
pub fn member_approved(state: &AppState, user_id: Uuid) {
    notify_user(
        state,
        user_id,
        PushPayload::new(
            "✅ Welcome to RallyUp!",
            "Your access has been approved.",
            "/home",
            "account",
        ),
        cat::ACCOUNT,
    );
}

pub fn member_rejected(state: &AppState, user_id: Uuid) {
    notify_user(
        state,
        user_id,
        PushPayload::new(
            "ℹ️ Join request",
            "Your join request was not approved.",
            "/",
            "account",
        ),
        cat::ACCOUNT,
    );
}

/// Yes-vote notification with the 90-second batching window (PRD §8.4).
///
/// The first Yes-voter in a window fires an immediate notification and opens
/// the window; subsequent voters are queued and flushed as one digest when the
/// window closes.
pub fn vote_yes(state: &AppState, group_id: Uuid, poll_id: Uuid, voter_name: &str, yes_count: i64) {
    let state = state.clone();
    let voter_name = voter_name.to_string();
    tokio::spawn(async move {
        let Some(mut r) = state.redis.clone() else {
            // No Redis → no batching state; just send immediately.
            send_vote_push(&state, group_id, &format!("{voter_name} voted Yes"), yes_count);
            return;
        };

        let window_key = format!("vote_batch:{poll_id}");
        let pending_key = format!("vote_batch_names:{poll_id}");

        // SET NX: are we the first voter in a new window?
        let set_res: redis::RedisResult<Option<String>> = redis::cmd("SET")
            .arg(&window_key)
            .arg(1)
            .arg("NX")
            .arg("EX")
            .arg(90)
            .query_async(&mut r)
            .await;
        let first = set_res.map(|res| res.is_some()).unwrap_or(true);

        if first {
            send_vote_push(&state, group_id, &format!("{voter_name} voted Yes"), yes_count);
            // Open the digest timer.
            let state2 = state.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(90)).await;
                flush_vote_digest(&state2, group_id, poll_id).await;
            });
        } else {
            let _: Result<(), _> = r.rpush(&pending_key, &voter_name).await;
            let _: Result<(), _> = r.expire(&pending_key, 120).await;
        }
    });
}

async fn flush_vote_digest(state: &AppState, group_id: Uuid, poll_id: Uuid) {
    let Some(mut r) = state.redis.clone() else { return };
    let pending_key = format!("vote_batch_names:{poll_id}");
    let names: Vec<String> = r.lrange(&pending_key, 0, -1).await.unwrap_or_default();
    let _: Result<(), _> = r.del(&pending_key).await;
    if names.is_empty() {
        return;
    }

    let yes_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM poll_votes WHERE poll_id = $1 AND vote = 'yes'")
            .bind(poll_id)
            .fetch_one(&state.db)
            .await
            .unwrap_or(0);

    let body = match names.len() {
        1 => format!("{} voted — {yes_count} Yes so far!", names[0]),
        2 => format!("{} and {} voted — {yes_count} Yes so far!", names[0], names[1]),
        n => format!(
            "{}, {} and {} others voted — {yes_count} Yes so far!",
            names[0],
            names[1],
            n - 2
        ),
    };
    send_vote_push(state, group_id, &body, yes_count);
}

fn send_vote_push(state: &AppState, group_id: Uuid, body: &str, yes_count: i64) {
    notify_group(
        state,
        group_id,
        PushPayload::new(
            format!("🏸 {yes_count} Yes for tonight"),
            body.to_string(),
            "/home",
            "votes",
        ),
        None,
        cat::VOTES,
    );
}
