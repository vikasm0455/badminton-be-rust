use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::{AdminUser, revoke_all_for_user};
use crate::error::ApiError;
use crate::models::ApiResponse;
use crate::security::{self, event};
use crate::state::AppState;
use crate::{email, notify, otp};

// ---- members ---------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct MemberRow {
    pub id: Uuid,
    pub display_name: String,
    pub email: String,
    pub role: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub approved_at: Option<DateTime<Utc>>,
    pub last_active_at: Option<DateTime<Utc>>,
    pub approved_by_name: Option<String>,
}

pub async fn list_members(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<ApiResponse<Vec<MemberRow>>>, ApiError> {
    let rows: Vec<MemberRow> = sqlx::query_as(
        "SELECT u.id, u.display_name, u.email, u.role, u.status, u.created_at, u.approved_at,
                u.last_active_at, a.display_name AS approved_by_name
         FROM users u LEFT JOIN users a ON a.id = u.approved_by
         ORDER BY CASE u.status WHEN 'pending' THEN 0 WHEN 'active' THEN 1 ELSE 2 END, u.created_at DESC",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(ApiResponse::ok(rows)))
}

async fn fetch_user(state: &AppState, id: Uuid) -> Result<(String, String, String), ApiError> {
    sqlx::query_as::<_, (String, String, String)>(
        "SELECT email, display_name, status FROM users WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)
}

pub async fn approve_member(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    let (email_addr, name, status) = fetch_user(&state, id).await?;
    if status != "pending" {
        return Err(ApiError::Conflict("Only pending members can be approved.".into()));
    }
    sqlx::query(
        "UPDATE users SET status = 'active', approved_at = NOW(), approved_by = $1 WHERE id = $2",
    )
    .bind(admin.id)
    .bind(id)
    .execute(&state.db)
    .await?;
    security::log(&state, event::MEMBER_APPROVED, Some(admin.id), None, json!({ "member": id })).await;
    email::send_approved(&state, &email_addr, &name).await.ok();
    notify::member_approved(&state, id);
    Ok(Json(ApiResponse::message("Member approved.")))
}

pub async fn reject_member(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    let (email_addr, name, status) = fetch_user(&state, id).await?;
    if status != "pending" {
        return Err(ApiError::Conflict("Only pending members can be rejected.".into()));
    }
    sqlx::query("UPDATE users SET status = 'rejected' WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;
    security::log(&state, event::MEMBER_REJECTED, Some(admin.id), None, json!({ "member": id })).await;
    email::send_rejected(&state, &email_addr, &name).await.ok();
    notify::member_rejected(&state, id);
    Ok(Json(ApiResponse::message("Member rejected.")))
}

pub async fn deactivate_member(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    if id == admin.id {
        return Err(ApiError::BadRequest("You can't deactivate yourself.".into()));
    }
    let res = sqlx::query(
        "UPDATE users SET status = 'deactivated', deactivated_at = NOW() WHERE id = $1",
    )
    .bind(id)
    .execute(&state.db)
    .await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    revoke_all_for_user(&state, id).await; // invalidate all sessions immediately
    security::log(&state, event::MEMBER_DEACTIVATED, Some(admin.id), None, json!({ "member": id })).await;
    Ok(Json(ApiResponse::message("Member deactivated.")))
}

pub async fn reactivate_member(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    let (email_addr, name, status) = fetch_user(&state, id).await?;
    if status != "deactivated" {
        return Err(ApiError::Conflict("Only deactivated members can be reactivated.".into()));
    }
    sqlx::query("UPDATE users SET status = 'active', deactivated_at = NULL WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;
    security::log(&state, event::MEMBER_REACTIVATED, Some(admin.id), None, json!({ "member": id })).await;
    email::send_reactivated(&state, &email_addr, &name).await.ok();
    Ok(Json(ApiResponse::message("Member reactivated.")))
}

pub async fn clear_lock(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    let (email_addr, _, _) = fetch_user(&state, id).await?;
    otp::clear_account_lock(&state, &email_addr.to_lowercase()).await;
    security::log(&state, event::ADMIN_ACTION, Some(admin.id), None, json!({ "action": "clear_lock", "member": id })).await;
    Ok(Json(ApiResponse::message("Lockout cleared.")))
}

#[derive(Serialize)]
pub struct MemberDetail {
    pub member: MemberRow,
    pub total_votes: i64,
    pub total_attendance: i64,
    // kCal is private to each member and intentionally NOT exposed to admins.
}

pub async fn member_detail(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<MemberDetail>>, ApiError> {
    let member: MemberRow = sqlx::query_as(
        "SELECT u.id, u.display_name, u.email, u.role, u.status, u.created_at, u.approved_at,
                u.last_active_at, a.display_name AS approved_by_name
         FROM users u LEFT JOIN users a ON a.id = u.approved_by WHERE u.id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;

    let total_votes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM poll_votes WHERE user_id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await?;
    let total_attendance: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM attendance WHERE user_id = $1")
            .bind(id)
            .fetch_one(&state.db)
            .await?;
    Ok(Json(ApiResponse::ok(MemberDetail {
        member,
        total_votes,
        total_attendance,
    })))
}

// ---- invites ---------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct InviteRow {
    pub id: Uuid,
    pub code: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub used_by_name: Option<String>,
    pub used_by_email: Option<String>,
    /// Derived: active | used | expired | revoked.
    #[sqlx(default)]
    pub computed_status: String,
}

pub async fn list_invites(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<ApiResponse<Vec<InviteRow>>>, ApiError> {
    let mut rows: Vec<InviteRow> = sqlx::query_as(
        "SELECT i.id, i.code, i.created_at, i.expires_at, i.used_at, i.revoked_at,
                u.display_name AS used_by_name, u.email AS used_by_email
         FROM invite_codes i LEFT JOIN users u ON u.id = i.used_by
         ORDER BY i.created_at DESC LIMIT 200",
    )
    .fetch_all(&state.db)
    .await?;
    let now = Utc::now();
    for r in &mut rows {
        r.computed_status = if r.revoked_at.is_some() {
            "revoked"
        } else if r.used_at.is_some() {
            "used"
        } else if r.expires_at <= now {
            "expired"
        } else {
            "active"
        }
        .to_string();
    }
    Ok(Json(ApiResponse::ok(rows)))
}

#[derive(Deserialize)]
pub struct GenerateInvitesReq {
    pub count: Option<i64>,
}

pub async fn generate_invites(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<GenerateInvitesReq>,
) -> Result<Json<ApiResponse<Vec<InviteRow>>>, ApiError> {
    let count = req.count.unwrap_or(1).clamp(1, 10);
    let expires_at = Utc::now() + Duration::hours(48);
    let mut created = Vec::new();
    for _ in 0..count {
        let code = random_code();
        let row: (Uuid, DateTime<Utc>, DateTime<Utc>) = sqlx::query_as(
            "INSERT INTO invite_codes (code, created_by, expires_at) VALUES ($1, $2, $3)
             RETURNING id, created_at, expires_at",
        )
        .bind(&code)
        .bind(admin.id)
        .bind(expires_at)
        .fetch_one(&state.db)
        .await?;
        created.push(InviteRow {
            id: row.0,
            code,
            created_at: row.1,
            expires_at: row.2,
            used_at: None,
            revoked_at: None,
            used_by_name: None,
            used_by_email: None,
            computed_status: "active".into(),
        });
    }
    security::log(&state, event::INVITE_CREATED, Some(admin.id), None, json!({ "count": count })).await;
    Ok(Json(ApiResponse::ok(created)))
}

pub async fn revoke_invite(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    let res = sqlx::query(
        "UPDATE invite_codes SET revoked_at = NOW() WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL",
    )
    .bind(id)
    .execute(&state.db)
    .await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::Conflict("This invite can no longer be revoked.".into()));
    }
    security::log(&state, event::INVITE_REVOKED, Some(admin.id), None, json!({ "invite": id })).await;
    Ok(Json(ApiResponse::message("Invite revoked.")))
}

fn random_code() -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..12)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

// ---- security log ----------------------------------------------------------

#[derive(Deserialize)]
pub struct SecurityQuery {
    pub event_type: Option<String>,
    pub user_id: Option<Uuid>,
    pub ip: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct SecurityEventRow {
    pub id: Uuid,
    pub event_type: String,
    pub user_id: Option<Uuid>,
    pub user_name: Option<String>,
    pub ip_address: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

pub async fn security_log(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(q): Query<SecurityQuery>,
) -> Result<Json<ApiResponse<Vec<SecurityEventRow>>>, ApiError> {
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let offset = q.offset.unwrap_or(0).max(0);
    let from = q.from.as_deref().and_then(|s| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok());
    let to = q.to.as_deref().and_then(|s| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok());

    let rows: Vec<SecurityEventRow> = sqlx::query_as(
        "SELECT e.id, e.event_type, e.user_id, u.display_name AS user_name,
                host(e.ip_address) AS ip_address, e.metadata, e.created_at
         FROM security_events e LEFT JOIN users u ON u.id = e.user_id
         WHERE ($1::text IS NULL OR e.event_type = $1)
           AND ($2::uuid IS NULL OR e.user_id = $2)
           AND ($3::text IS NULL OR host(e.ip_address) = $3)
           AND ($4::date IS NULL OR e.created_at >= $4::date)
           AND ($5::date IS NULL OR e.created_at < ($5::date + INTERVAL '1 day'))
         ORDER BY e.created_at DESC
         LIMIT $6 OFFSET $7",
    )
    .bind(q.event_type)
    .bind(q.user_id)
    .bind(q.ip)
    .bind(from)
    .bind(to)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(ApiResponse::ok(rows)))
}

// ---- data / health ---------------------------------------------------------

#[derive(Serialize)]
pub struct SystemHealth {
    pub db: bool,
    pub redis: bool,
    pub last_jobs: serde_json::Value,
}

pub async fn system_health(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<ApiResponse<SystemHealth>>, ApiError> {
    let db = sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&state.db).await.is_ok();
    let redis = match state.redis.clone() {
        Some(mut r) => {
            let pong: redis::RedisResult<String> = redis::cmd("PING").query_async(&mut r).await;
            pong.is_ok()
        }
        None => false,
    };
    let last_jobs: Vec<(String, String)> = sqlx::query_as(
        "SELECT key, value FROM app_config WHERE key LIKE 'job_last_%'",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    let map: serde_json::Map<String, serde_json::Value> = last_jobs
        .into_iter()
        .map(|(k, v)| (k.trim_start_matches("job_last_").to_string(), json!(v)))
        .collect();
    Ok(Json(ApiResponse::ok(SystemHealth {
        db,
        redis,
        last_jobs: serde_json::Value::Object(map),
    })))
}
