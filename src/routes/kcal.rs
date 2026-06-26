use axum::Json;
use axum::extract::State;
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::models::ApiResponse;
use crate::state::{AppState, LiveEvent};
use crate::time;

#[derive(Serialize)]
pub struct MyLog {
    pub kcal: i16,
    pub note: Option<String>,
}

/// kCal is private to each member — never aggregated or shared. `today` returns
/// only the caller's own log.
#[derive(Serialize)]
pub struct KcalToday {
    pub my_log: Option<MyLog>,
}

pub async fn today(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<ApiResponse<KcalToday>>, ApiError> {
    let game_date = time::today();
    let my_log = sqlx::query_as::<_, (i16, Option<String>)>(
        "SELECT kcal, note FROM kcal_logs WHERE user_id = $1 AND game_date = $2",
    )
    .bind(user.id)
    .bind(game_date)
    .fetch_optional(&state.db)
    .await?
    .map(|(kcal, note)| MyLog { kcal, note });

    Ok(Json(ApiResponse::ok(KcalToday { my_log })))
}

#[derive(Deserialize)]
pub struct LogKcalReq {
    pub kcal: i16,
    pub note: Option<String>,
    /// Optional YYYY-MM-DD; defaults to today.
    pub game_date: Option<String>,
}

pub async fn log(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<LogKcalReq>,
) -> Result<Json<ApiResponse<KcalToday>>, ApiError> {
    if !(0..=2000).contains(&req.kcal) {
        return Err(ApiError::BadRequest("kcal must be between 0 and 2000".into()));
    }
    let note = req.note.as_deref().map(str::trim).filter(|n| !n.is_empty());
    if let Some(n) = note {
        if n.chars().count() > 100 {
            return Err(ApiError::BadRequest("note must be 100 characters or fewer".into()));
        }
    }
    let game_date = match &req.game_date {
        Some(s) => NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d")
            .map_err(|_| ApiError::BadRequest("invalid date".into()))?,
        None => time::today(),
    };

    sqlx::query(
        "INSERT INTO kcal_logs (user_id, game_date, kcal, note) VALUES ($1, $2, $3, $4)
         ON CONFLICT (user_id, game_date)
         DO UPDATE SET kcal = EXCLUDED.kcal, note = EXCLUDED.note, logged_at = NOW()",
    )
    .bind(user.id)
    .bind(game_date)
    .bind(req.kcal)
    .bind(note)
    .execute(&state.db)
    .await?;

    state.broadcast(LiveEvent::KcalChanged);
    today(State(state), user).await
}

#[derive(Serialize, sqlx::FromRow)]
pub struct HistoryPoint {
    pub game_date: NaiveDate,
    pub kcal: i16,
}

#[derive(Serialize)]
pub struct KcalHistory {
    pub points: Vec<HistoryPoint>,
    pub total_sessions: i64,
    pub avg_kcal: i64,
    pub max_kcal: i16,
}

pub async fn history(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<ApiResponse<KcalHistory>>, ApiError> {
    // Last 14 sessions for the chart (oldest→newest for left-to-right plotting).
    let mut points: Vec<HistoryPoint> = sqlx::query_as(
        "SELECT game_date, kcal FROM kcal_logs WHERE user_id = $1 ORDER BY game_date DESC LIMIT 14",
    )
    .bind(user.id)
    .fetch_all(&state.db)
    .await?;
    points.reverse();

    let stats: (i64, Option<f64>, Option<i16>) = sqlx::query_as(
        "SELECT COUNT(*), AVG(kcal)::float8, MAX(kcal) FROM kcal_logs WHERE user_id = $1",
    )
    .bind(user.id)
    .fetch_one(&state.db)
    .await?;

    Ok(Json(ApiResponse::ok(KcalHistory {
        points,
        total_sessions: stats.0,
        avg_kcal: stats.1.unwrap_or(0.0).round() as i64,
        max_kcal: stats.2.unwrap_or(0),
    })))
}
