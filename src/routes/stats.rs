//! Personal analytics: aggregates the caller's OWN history across all their
//! groups. Private — nothing here is ever group-visible.
//!
//! A "session" is a day the user was in a poll's confirmed attendance list,
//! or — for polls where attendance was never confirmed — a day they voted yes.

use axum::Json;
use axum::extract::State;
use chrono::{Datelike, Duration, NaiveDate};
use serde::Serialize;
use std::collections::BTreeSet;

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::models::ApiResponse;
use crate::state::AppState;
use crate::time;

#[derive(Serialize)]
pub struct WeekBucket {
    pub week_start: NaiveDate,
    pub sessions: i64,
}

#[derive(Serialize)]
pub struct KcalPoint {
    pub date: NaiveDate,
    pub kcal: i16,
}

#[derive(Serialize)]
pub struct MyStats {
    pub sessions_total: i64,
    pub sessions_this_month: i64,
    pub sessions_last_month: i64,
    pub current_streak_weeks: i64,
    pub best_streak_weeks: i64,
    pub court_minutes_this_month: i64,
    pub court_minutes_last_month: i64,
    pub avg_kcal_per_session: Option<i64>,
    pub yes_rate_percent: Option<i64>,
    pub weekly_sessions: Vec<WeekBucket>, // last 8 weeks incl. current, oldest first
    pub kcal_series: Vec<KcalPoint>,      // last 30 days, oldest first
}

fn week_start(d: NaiveDate) -> NaiveDate {
    d - Duration::days(d.weekday().num_days_from_monday() as i64)
}

pub async fn me(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<ApiResponse<MyStats>>, ApiError> {
    let today = time::today();

    // Only days that already happened; the yes-vote fallback never applies to
    // locked polls (locked + zero attendance rows = confirmed nobody played).
    let session_dates: Vec<NaiveDate> = sqlx::query_scalar(
        "SELECT DISTINCT p.game_date FROM polls p
         WHERE p.game_date <= $2
           AND (EXISTS (SELECT 1 FROM attendance a WHERE a.poll_id = p.id AND a.user_id = $1)
            OR (NOT p.attendance_locked
                AND NOT EXISTS (SELECT 1 FROM attendance a2 WHERE a2.poll_id = p.id)
                AND EXISTS (SELECT 1 FROM poll_votes v
                            WHERE v.poll_id = p.id AND v.user_id = $1 AND v.vote = 'yes')))
         ORDER BY p.game_date",
    )
    .bind(user.id)
    .bind(today)
    .fetch_all(&state.db)
    .await?;

    let month_start = NaiveDate::from_ymd_opt(today.year(), today.month(), 1).unwrap();
    let last_month_start = if today.month() == 1 {
        NaiveDate::from_ymd_opt(today.year() - 1, 12, 1)
    } else {
        NaiveDate::from_ymd_opt(today.year(), today.month() - 1, 1)
    }
    .unwrap();

    let sessions_total = session_dates.len() as i64;
    let sessions_this_month = session_dates.iter().filter(|d| **d >= month_start).count() as i64;
    let sessions_last_month = session_dates
        .iter()
        .filter(|d| **d >= last_month_start && **d < month_start)
        .count() as i64;

    // Week streaks over distinct played weeks. The current week counts when
    // played; an unplayed current week doesn't break the streak (it isn't
    // over yet) — the chain is just counted from last week.
    let weeks: BTreeSet<NaiveDate> = session_dates.iter().map(|d| week_start(*d)).collect();
    let this_week = week_start(today);
    let mut cursor = this_week;
    if !weeks.contains(&cursor) {
        cursor -= Duration::days(7);
    }
    let mut current_streak_weeks = 0i64;
    while weeks.contains(&cursor) {
        current_streak_weeks += 1;
        cursor -= Duration::days(7);
    }
    let mut best_streak_weeks = 0i64;
    let mut run = 0i64;
    let mut prev: Option<NaiveDate> = None;
    for w in &weeks {
        run = match prev {
            Some(p) if *w - p == Duration::days(7) => run + 1,
            _ => 1,
        };
        best_streak_weeks = best_streak_weeks.max(run);
        prev = Some(*w);
    }

    let mut weekly_sessions = Vec::with_capacity(8);
    for i in (0..8i64).rev() {
        let ws = this_week - Duration::days(7 * i);
        let sessions = session_dates
            .iter()
            .filter(|d| **d >= ws && **d < ws + Duration::days(7))
            .count() as i64;
        weekly_sessions.push(WeekBucket { week_start: ws, sessions });
    }

    let (court_minutes_this_month,): (i64,) = sqlx::query_as(
        "SELECT COALESCE(SUM(duration_minutes), 0)::BIGINT FROM court_reservations
         WHERE reserved_by = $1 AND status != 'cancelled' AND game_date >= $2",
    )
    .bind(user.id)
    .bind(month_start)
    .fetch_one(&state.db)
    .await?;
    let (court_minutes_last_month,): (i64,) = sqlx::query_as(
        "SELECT COALESCE(SUM(duration_minutes), 0)::BIGINT FROM court_reservations
         WHERE reserved_by = $1 AND status != 'cancelled'
           AND game_date >= $2 AND game_date < $3",
    )
    .bind(user.id)
    .bind(last_month_start)
    .bind(month_start)
    .fetch_one(&state.db)
    .await?;

    let kcal_rows: Vec<(NaiveDate, i16)> = sqlx::query_as(
        "SELECT game_date, kcal FROM kcal_logs
         WHERE user_id = $1 AND game_date > $2 ORDER BY game_date",
    )
    .bind(user.id)
    .bind(today - Duration::days(30))
    .fetch_all(&state.db)
    .await?;
    let (avg_kcal,): (Option<f64>,) = sqlx::query_as(
        "SELECT AVG(kcal)::FLOAT8 FROM kcal_logs WHERE user_id = $1 AND game_date > $2",
    )
    .bind(user.id)
    .bind(today - Duration::days(90))
    .fetch_one(&state.db)
    .await?;

    let (yes_votes, total_votes): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*) FILTER (WHERE vote = 'yes'), COUNT(*) FROM poll_votes WHERE user_id = $1",
    )
    .bind(user.id)
    .fetch_one(&state.db)
    .await?;

    Ok(Json(ApiResponse::ok(MyStats {
        sessions_total,
        sessions_this_month,
        sessions_last_month,
        current_streak_weeks,
        best_streak_weeks,
        court_minutes_this_month,
        court_minutes_last_month,
        avg_kcal_per_session: avg_kcal.map(|a| a.round() as i64),
        yes_rate_percent: (total_votes > 0)
            .then(|| (yes_votes as f64 / total_votes as f64 * 100.0).round() as i64),
        weekly_sessions,
        kcal_series: kcal_rows
            .into_iter()
            .map(|(date, kcal)| KcalPoint { date, kcal })
            .collect(),
    })))
}
