//! Courts v1 HTTP surface: platform console (OTP-gated), club-admin console
//! (argon2 password login), and the public kiosk endpoints. All domain
//! mutations live in crate::courts — this module is auth, envelopes, and the
//! open-hours gate.

use std::convert::Infallible;

use axum::Json;
use axum::async_trait;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use futures::Stream;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::{decode_token, is_revoked, issue_token_for, revoke_all_for_user};
use crate::courts::{self, ActionError, ClubRow, PlayerCred};
use crate::error::ApiError;
use crate::models::ApiResponse;
use crate::net::ClientIp;
use crate::otp::{self, OtpPurpose, VerifyResult};
use crate::state::AppState;
use crate::{email, time};

// ---- password hashing -------------------------------------------------------

fn hash_password(password: &str) -> Result<String, ApiError> {
    use argon2::password_hash::{SaltString, rand_core::OsRng};
    use argon2::{Argon2, PasswordHasher};
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| ApiError::Internal(format!("password hashing failed: {e}")))
}

fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};
    PasswordHash::new(hash)
        .map(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
        .unwrap_or(false)
}

/// A fixed argon2 hash verified when the login email is unknown, so the
/// unknown-email and wrong-password paths cost the same time (no
/// email-enumeration timing oracle).
fn dummy_hash() -> &'static str {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DUMMY.get_or_init(|| {
        hash_password("timing-equalizer-not-a-real-password").expect("argon2 dummy hash")
    })
}

/// Club-admin and platform tokens live 7 days — long enough for a console
/// session, short enough that a leaked token ages out fast.
const COURTS_TOKEN_DAYS: i64 = 7;

// ---- auth extractors --------------------------------------------------------

fn bearer_token(parts: &Parts) -> Option<String> {
    parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_string)
}

/// Platform-console session (role "platform"). Stateless — the OTP gate at
/// issue time is the identity check; there is no platform user row.
pub struct PlatformAdmin;

#[async_trait]
impl FromRequestParts<AppState> for PlatformAdmin {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let token = bearer_token(parts).ok_or(ApiError::Unauthorized)?;
        let claims = decode_token(&token, &state.config.jwt_secret).ok_or(ApiError::Unauthorized)?;
        if claims.role != "platform" {
            return Err(ApiError::Forbidden);
        }
        if is_revoked(state, &claims).await {
            return Err(ApiError::Unauthorized);
        }
        Ok(PlatformAdmin)
    }
}

/// A club-admin session token (role "club_admin"). Which club it may touch is
/// checked per-request against the {slug} in the path — see require_club_admin.
pub struct ClubAdminToken {
    pub admin_id: Uuid,
}

#[async_trait]
impl FromRequestParts<AppState> for ClubAdminToken {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let token = bearer_token(parts).ok_or(ApiError::Unauthorized)?;
        let claims = decode_token(&token, &state.config.jwt_secret).ok_or(ApiError::Unauthorized)?;
        if claims.role != "club_admin" {
            return Err(ApiError::Forbidden);
        }
        if is_revoked(state, &claims).await {
            return Err(ApiError::Unauthorized);
        }
        Ok(ClubAdminToken { admin_id: claims.sub })
    }
}

#[derive(sqlx::FromRow)]
struct AdminRow {
    #[allow(dead_code)]
    id: Uuid,
    email: String,
    name: String,
    password_hash: String,
    must_change: bool,
}

/// The admin must exist AND belong to the club named in the path. Returns the
/// club plus the admin's must_change flag; most handlers want the
/// require_club_admin wrapper below, which also refuses temp-password
/// sessions.
async fn admin_of_club(
    state: &AppState,
    slug: &str,
    token: &ClubAdminToken,
) -> Result<(ClubRow, bool), ApiError> {
    let club = courts::club_by_slug(&state.db, slug).await?.ok_or(ApiError::NotFound)?;
    let belongs: Option<(Uuid, bool)> =
        sqlx::query_as("SELECT id, must_change FROM club_admins WHERE id = $1 AND club_id = $2")
            .bind(token.admin_id)
            .bind(club.id)
            .fetch_optional(&state.db)
            .await?;
    let (_, must_change) = belongs.ok_or(ApiError::Forbidden)?;
    Ok((club, must_change))
}

/// Standard admin gate: a session opened with the emailed temp password may
/// do exactly one thing — set a real password. Everything else waits, so a
/// temp password sitting in an inbox is never a standing full-power key.
/// (admin_change_password uses admin_of_club directly.)
async fn require_club_admin(
    state: &AppState,
    slug: &str,
    token: &ClubAdminToken,
) -> Result<ClubRow, ApiError> {
    let (club, must_change) = admin_of_club(state, slug, token).await?;
    if must_change {
        return Err(ApiError::Conflict(
            "Set a new password to continue — your temporary password must be changed first."
                .into(),
        ));
    }
    Ok(club)
}

/// Suspended clubs are frozen for their admins too: the overview stays
/// readable, but every mutation is refused.
fn reject_suspended(club: &ClubRow) -> Result<(), ApiError> {
    if club.status == "suspended" {
        return Err(ApiError::Conflict(
            "This club is suspended — changes are disabled. Contact RallyUp support.".into(),
        ));
    }
    Ok(())
}

/// Opening hours are a same-day window; overnight (or empty) windows would
/// make open_now() permanently false, so they're rejected at config time.
fn hours_valid(opens_at: chrono::NaiveTime, closes_at: chrono::NaiveTime) -> bool {
    closes_at > opens_at
}

/// Kiosk view of a club: suspended clubs are invisible (404).
async fn kiosk_club(state: &AppState, slug: &str) -> Result<ClubRow, ApiError> {
    let club = courts::club_by_slug(&state.db, slug).await?.ok_or(ApiError::NotFound)?;
    if club.status == "suspended" {
        return Err(ApiError::NotFound);
    }
    Ok(club)
}

fn club_json(club: &ClubRow) -> Value {
    json!({
        "id": club.id,
        "slug": club.slug,
        "name": club.name,
        "brand_color": club.brand_color,
        "court_count": club.court_count,
        "session_minutes": club.session_minutes,
        "queue_depth": club.queue_depth,
        "auto_extend": club.auto_extend,
        "opens_at": club.opens_at.format("%H:%M").to_string(),
        "closes_at": club.closes_at.format("%H:%M").to_string(),
        "kiosk_theme": club.kiosk_theme,
        "status": club.status,
        "created_at": club.created_at.to_rfc3339(),
    })
}

/// UTC instant of today's local midnight — "today" filters for issued_at etc.
fn local_midnight_utc() -> DateTime<Utc> {
    time::la_datetime_to_utc(time::today(), chrono::NaiveTime::MIN)
}

// ---- platform: OTP login ----------------------------------------------------

#[derive(Deserialize)]
pub struct PlatformOtpReq {
    pub email: String,
}

/// Request a platform sign-in code. Only the env-designated platform admin
/// email actually receives one — everyone gets the same generic response so
/// the gate can't be probed.
pub async fn platform_otp(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<PlatformOtpReq>,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    let email = req.email.trim().to_lowercase();
    if !email.contains('@') {
        return Err(ApiError::BadRequest("a valid email is required".into()));
    }
    otp::check_request_limits(&state, &email, ip).await?;

    let gate = state.config.platform_admin_email.as_deref();
    if gate == Some(email.as_str()) {
        let (code, resend_after) = otp::store_code(&state, OtpPurpose::Platform, &email).await?;
        if resend_after == 0 {
            // Fire-and-forget: awaiting the Resend roundtrip inline would make
            // the gate email discoverable by response-time measurement.
            let st = state.clone();
            let to = email.clone();
            tokio::spawn(async move {
                email::send_otp(&st, &to, &code).await.ok();
            });
        }
    }
    Ok(Json(ApiResponse::ok(json!({
        "email": email,
        "expires_in_minutes": otp::OTP_TTL_SECS / 60,
        "delivery": if state.config.resend_api_key.is_some() { "email" } else { "server-log" },
    }))))
}

#[derive(Deserialize)]
pub struct PlatformVerifyReq {
    pub email: String,
    pub code: String,
}

pub async fn platform_verify(
    State(state): State<AppState>,
    Json(req): Json<PlatformVerifyReq>,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    let email = req.email.trim().to_lowercase();
    // One generic error for EVERY failure path (wrong email, wrong code,
    // expired code) so the platform admin address can't be probed.
    let generic =
        || ApiError::BadRequest("That code didn't work. Request a new code and try again.".into());
    if state.config.platform_admin_email.as_deref() != Some(email.as_str()) {
        // Equivalent Redis work to the real path so response time can't
        // distinguish the configured platform email from any other address.
        let _ =
            otp::verify_code(&state, OtpPurpose::Platform, "probe@invalid.local", req.code.trim())
                .await;
        return Err(generic());
    }
    match otp::verify_code(&state, OtpPurpose::Platform, &email, req.code.trim()).await? {
        VerifyResult::Ok => {}
        VerifyResult::Expired | VerifyResult::Wrong { .. } | VerifyResult::TooManyAttempts => {
            return Err(generic());
        }
    }
    // No platform user row exists; the role claim is the whole session. The
    // sub is DETERMINISTIC (v5 of the gate email) so revoke_all_for_user can
    // actually kill leaked platform tokens — a fresh random sub per login
    // would make them irrevocable for their whole lifetime.
    let sub = Uuid::new_v5(&Uuid::NAMESPACE_URL, format!("rallyup-platform:{email}").as_bytes());
    let token = issue_token_for(sub, "platform", &state.config.jwt_secret, COURTS_TOKEN_DAYS)?;
    Ok(Json(ApiResponse::ok(json!({ "token": token, "email": email }))))
}

// ---- platform: clubs --------------------------------------------------------

pub async fn platform_list_clubs(
    State(state): State<AppState>,
    _admin: PlatformAdmin,
) -> Result<Json<ApiResponse<Vec<Value>>>, ApiError> {
    let rows: Vec<(Uuid, String, String, i32, Option<String>, String, DateTime<Utc>, i64)> =
        sqlx::query_as(
            "SELECT c.id, c.slug, c.name, c.court_count,
                    (SELECT a.email FROM club_admins a WHERE a.club_id = c.id
                     ORDER BY a.created_at LIMIT 1) AS admin_email,
                    c.status, c.created_at,
                    (SELECT COUNT(DISTINCT s.court_number) FROM court_sessions s
                     WHERE s.club_id = c.id AND s.started_at >= $1) AS courts_active_today
             FROM clubs c ORDER BY c.created_at DESC",
        )
        .bind(local_midnight_utc())
        .fetch_all(&state.db)
        .await?;
    let out = rows
        .into_iter()
        .map(|(id, slug, name, court_count, admin_email, status, created_at, active)| {
            json!({
                "id": id,
                "slug": slug,
                "name": name,
                "court_count": court_count,
                "admin_email": admin_email,
                "status": status,
                "created_at": created_at.to_rfc3339(),
                "courts_active_today": active,
            })
        })
        .collect();
    Ok(Json(ApiResponse::ok(out)))
}

#[derive(Deserialize)]
pub struct CreateClubReq {
    pub name: String,
    pub slug: String,
    pub brand_color: Option<String>,
    pub court_count: i32,
    pub session_minutes: Option<i32>,
    pub queue_depth: Option<i32>,
    pub admin_name: String,
    pub admin_email: String,
}

fn valid_slug(slug: &str) -> bool {
    (3..=32).contains(&slug.len())
        && slug.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn valid_color(color: &str) -> bool {
    color.len() == 7
        && color.starts_with('#')
        && color[1..].chars().all(|c| c.is_ascii_hexdigit())
}

/// Onboard a club: club row + seeded courts + first admin with an emailed
/// temp password (must_change).
pub async fn platform_create_club(
    State(state): State<AppState>,
    _admin: PlatformAdmin,
    Json(req): Json<CreateClubReq>,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    let slug = req.slug.trim().to_lowercase();
    let name = req.name.trim().to_string();
    let admin_email = req.admin_email.trim().to_lowercase();
    let admin_name = req.admin_name.trim().to_string();
    if !valid_slug(&slug) {
        return Err(ApiError::BadRequest("slug must be 3–32 chars of a-z, 0-9 or '-'".into()));
    }
    if name.is_empty() || name.chars().count() > 60 {
        return Err(ApiError::BadRequest("club name must be 1–60 characters".into()));
    }
    if !admin_email.contains('@') {
        return Err(ApiError::BadRequest("a valid admin email is required".into()));
    }
    if admin_name.is_empty() {
        return Err(ApiError::BadRequest("admin name is required".into()));
    }
    if !(1..=50).contains(&req.court_count) {
        return Err(ApiError::BadRequest("court count must be between 1 and 50".into()));
    }
    let session_minutes = req.session_minutes.unwrap_or(45);
    if !(5..=240).contains(&session_minutes) {
        return Err(ApiError::BadRequest("session minutes must be between 5 and 240".into()));
    }
    let queue_depth = req.queue_depth.unwrap_or(3);
    if !(1..=10).contains(&queue_depth) {
        return Err(ApiError::BadRequest("queue depth must be between 1 and 10".into()));
    }
    let brand_color = req.brand_color.unwrap_or_else(|| "#b06f3c".to_string());
    if !valid_color(&brand_color) {
        return Err(ApiError::BadRequest("brand color must be a #rrggbb hex value".into()));
    }

    let temp_password = courts::generate_admin_password();
    let password_hash = hash_password(&temp_password)?;

    let mut tx = state.db.begin().await?;
    let club: Result<ClubRow, sqlx::Error> = sqlx::query_as(&format!(
        "INSERT INTO clubs (slug, name, brand_color, court_count, session_minutes, queue_depth)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING {}",
        courts::CLUB_COLUMNS
    ))
    .bind(&slug)
    .bind(&name)
    .bind(&brand_color)
    .bind(req.court_count)
    .bind(session_minutes)
    .bind(queue_depth)
    .fetch_one(&mut *tx)
    .await;
    let club = club.map_err(|e| match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            ApiError::Conflict(format!("The slug \"{slug}\" is already taken."))
        }
        _ => ApiError::Db(e),
    })?;
    for n in 1..=req.court_count {
        sqlx::query("INSERT INTO club_courts (club_id, number) VALUES ($1, $2)")
            .bind(club.id)
            .bind(n)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query(
        "INSERT INTO club_admins (club_id, email, name, password_hash) VALUES ($1, $2, $3, $4)",
    )
    .bind(club.id)
    .bind(&admin_email)
    .bind(&admin_name)
    .bind(&password_hash)
    .execute(&mut *tx)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            ApiError::Conflict(format!("{admin_email} already administers a club."))
        }
        _ => ApiError::Db(e),
    })?;
    tx.commit().await?;

    let invite_emailed =
        email::send_club_admin_invite(&state, &admin_email, &name, &slug, &temp_password)
            .await
            .is_ok();
    tracing::info!(slug, admin_email, invite_emailed, "club onboarded");

    Ok(Json(ApiResponse::ok(json!({
        "club": club_json(&club),
        "invite_emailed": invite_emailed,
    }))))
}

#[derive(Deserialize)]
pub struct PatchClubReq {
    pub status: Option<String>,
}

pub async fn platform_patch_club(
    State(state): State<AppState>,
    _admin: PlatformAdmin,
    Path(id): Path<Uuid>,
    Json(req): Json<PatchClubReq>,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    if let Some(status) = &req.status {
        if !matches!(status.as_str(), "onboarding" | "live" | "suspended") {
            return Err(ApiError::BadRequest("status must be onboarding, live or suspended".into()));
        }
        let updated = sqlx::query("UPDATE clubs SET status = $1 WHERE id = $2")
            .bind(status)
            .bind(id)
            .execute(&state.db)
            .await?;
        if updated.rows_affected() == 0 {
            return Err(ApiError::NotFound);
        }
        if status == "suspended" {
            // A suspension locks the operators out too: kill every admin
            // session for this club so stolen/retained tokens die with it.
            let admin_ids: Vec<(Uuid,)> =
                sqlx::query_as("SELECT id FROM club_admins WHERE club_id = $1")
                    .bind(id)
                    .fetch_all(&state.db)
                    .await?;
            for (admin_id,) in admin_ids {
                revoke_all_for_user(&state, admin_id).await;
            }
        }
        state.notify_club(id); // kiosks learn about suspension on the next nudge
    }
    let club: ClubRow = sqlx::query_as(&format!(
        "SELECT {} FROM clubs WHERE id = $1",
        courts::CLUB_COLUMNS
    ))
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(ApiResponse::ok(club_json(&club))))
}

// ---- club admin: auth -------------------------------------------------------

#[derive(Deserialize)]
pub struct AdminLoginReq {
    pub email: String,
    pub password: String,
}

pub async fn admin_login(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Json(req): Json<AdminLoginReq>,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    let club = courts::club_by_slug(&state.db, &slug).await?.ok_or(ApiError::NotFound)?;
    let email = req.email.trim().to_lowercase();
    // Per-email lockout, namespaced per club, reusing the OTP lockout
    // machinery (10 failures / 24h window).
    let lock_scope = format!("club-admin:{}:{email}", club.id);
    if otp::is_account_locked(&state, &lock_scope).await {
        return Err(ApiError::RateLimited(
            "Too many failed sign-ins. Please try again later.".into(),
        ));
    }
    let admin: Option<AdminRow> = sqlx::query_as(
        "SELECT id, email, name, password_hash, must_change
         FROM club_admins WHERE club_id = $1 AND LOWER(email) = $2",
    )
    .bind(club.id)
    .bind(&email)
    .fetch_optional(&state.db)
    .await?;
    // Same message for unknown email and wrong password.
    let bad = || ApiError::BadRequest("Incorrect email or password.".into());
    let Some(admin) = admin else {
        // Unknown email: burn the same argon2 time as a real verification so
        // response timing can't enumerate admin emails.
        verify_password(req.password.trim(), dummy_hash());
        otp::note_login_failure(&state, &lock_scope).await;
        return Err(bad());
    };
    if !verify_password(req.password.trim(), &admin.password_hash) {
        otp::note_login_failure(&state, &lock_scope).await;
        return Err(bad());
    }
    let token =
        issue_token_for(admin.id, "club_admin", &state.config.jwt_secret, COURTS_TOKEN_DAYS)?;
    Ok(Json(ApiResponse::ok(json!({
        "token": token,
        "must_change": admin.must_change,
        "name": admin.name,
        "email": admin.email,
        "club": { "slug": club.slug, "name": club.name },
    }))))
}

#[derive(Deserialize)]
pub struct ChangePasswordReq {
    pub current: String,
    pub new: String,
}

pub async fn admin_change_password(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    token: ClubAdminToken,
    Json(req): Json<ChangePasswordReq>,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    // Deliberately NOT require_club_admin: this is the one endpoint a
    // temp-password (must_change) session is allowed to reach.
    admin_of_club(&state, &slug, &token).await?;
    let new = req.new.trim();
    if new.chars().count() < 8 {
        return Err(ApiError::BadRequest("New password must be at least 8 characters.".into()));
    }
    let hash: String =
        sqlx::query_scalar("SELECT password_hash FROM club_admins WHERE id = $1")
            .bind(token.admin_id)
            .fetch_one(&state.db)
            .await?;
    if !verify_password(req.current.trim(), &hash) {
        return Err(ApiError::BadRequest("Current password is incorrect.".into()));
    }
    sqlx::query("UPDATE club_admins SET password_hash = $1, must_change = FALSE WHERE id = $2")
        .bind(hash_password(new)?)
        .bind(token.admin_id)
        .execute(&state.db)
        .await?;
    // A password change invalidates every outstanding session (including the
    // one making this request) — hand back a fresh token so the console
    // continues seamlessly.
    revoke_all_for_user(&state, token.admin_id).await;
    let fresh =
        issue_token_for(token.admin_id, "club_admin", &state.config.jwt_secret, COURTS_TOKEN_DAYS)?;
    Ok(Json(ApiResponse::ok_msg(json!({ "token": fresh }), "Password updated.")))
}

// ---- club admin: overview / config ------------------------------------------

pub async fn admin_overview(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    token: ClubAdminToken,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    let club = require_club_admin(&state, &slug, &token).await?;

    let (players_on_court,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM session_players sp
         JOIN court_sessions cs ON cs.id = sp.session_id
         WHERE cs.club_id = $1 AND cs.status = 'active'",
    )
    .bind(club.id)
    .fetch_one(&state.db)
    .await?;
    let (groups_queued,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM court_queues WHERE club_id = $1")
            .bind(club.id)
            .fetch_one(&state.db)
            .await?;
    let (credentials_today,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM club_credentials WHERE club_id = $1 AND issued_at >= $2",
    )
    .bind(club.id)
    .bind(local_midnight_utc())
    .fetch_one(&state.db)
    .await?;
    let courts: Vec<(i32, bool, Option<String>)> = sqlx::query_as(
        "SELECT number, closed, closed_reason FROM club_courts WHERE club_id = $1 ORDER BY number",
    )
    .bind(club.id)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(ApiResponse::ok(json!({
        "config": club_json(&club),
        "stats": {
            "courts": club.court_count,
            "players_on_court": players_on_court,
            "groups_queued": groups_queued,
            "credentials_today": credentials_today,
        },
        "courts": courts
            .into_iter()
            .map(|(number, closed, closed_reason)| json!({
                "number": number, "closed": closed, "closed_reason": closed_reason,
            }))
            .collect::<Vec<_>>(),
    }))))
}

#[derive(Deserialize)]
pub struct PatchConfigReq {
    pub court_count: Option<i32>,
    pub session_minutes: Option<i32>,
    pub queue_depth: Option<i32>,
    pub auto_extend: Option<bool>,
    pub opens_at: Option<String>,
    pub closes_at: Option<String>,
    pub kiosk_theme: Option<String>,
    pub brand_color: Option<String>,
}

pub async fn admin_patch_config(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    token: ClubAdminToken,
    Json(req): Json<PatchConfigReq>,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    let club = require_club_admin(&state, &slug, &token).await?;
    reject_suspended(&club)?;

    // Validate EVERY field before touching the database, so a bad later field
    // can never leave the config half-applied.
    if let Some(n) = req.court_count {
        if !(1..=50).contains(&n) {
            return Err(ApiError::BadRequest("court count must be between 1 and 50".into()));
        }
    }
    if let Some(m) = req.session_minutes {
        if !(5..=240).contains(&m) {
            return Err(ApiError::BadRequest("session minutes must be between 5 and 240".into()));
        }
    }
    if let Some(d) = req.queue_depth {
        if !(1..=10).contains(&d) {
            return Err(ApiError::BadRequest("queue depth must be between 1 and 10".into()));
        }
    }
    let opens_at = match &req.opens_at {
        Some(raw) => Some(
            time::parse_hhmm(raw)
                .ok_or_else(|| ApiError::BadRequest("opens_at must be HH:MM".into()))?,
        ),
        None => None,
    };
    let closes_at = match &req.closes_at {
        Some(raw) => Some(
            time::parse_hhmm(raw)
                .ok_or_else(|| ApiError::BadRequest("closes_at must be HH:MM".into()))?,
        ),
        None => None,
    };
    // The pair must stay a valid same-day window after the patch.
    if !hours_valid(opens_at.unwrap_or(club.opens_at), closes_at.unwrap_or(club.closes_at)) {
        return Err(ApiError::BadRequest(
            "closing time must be after opening time".into(),
        ));
    }
    if let Some(theme) = &req.kiosk_theme {
        if !matches!(theme.as_str(), "light" | "dark") {
            return Err(ApiError::BadRequest("kiosk theme must be light or dark".into()));
        }
    }
    if let Some(color) = &req.brand_color {
        if !valid_color(color) {
            return Err(ApiError::BadRequest("brand color must be a #rrggbb hex value".into()));
        }
    }

    // Apply everything in ONE transaction (the court-shrink advisory locks
    // live inside it), then broadcast once after commit.
    let mut tx = state.db.begin().await?;
    // Re-validate the hours window against the CURRENT row under FOR UPDATE —
    // two concurrent partial patches, each valid against the same stale
    // snapshot, could otherwise compose into an inverted (always-closed)
    // window. The row lock also serializes the patches themselves.
    let (cur_open, cur_close): (chrono::NaiveTime, chrono::NaiveTime) =
        sqlx::query_as("SELECT opens_at, closes_at FROM clubs WHERE id = $1 FOR UPDATE")
            .bind(club.id)
            .fetch_one(&mut *tx)
            .await?;
    if !hours_valid(opens_at.unwrap_or(cur_open), closes_at.unwrap_or(cur_close)) {
        return Err(ApiError::BadRequest("closing time must be after opening time".into()));
    }
    if let Some(n) = req.court_count {
        courts::resize_courts(&mut tx, club.id, n).await.map_err(|e| match e {
            ActionError::Court(msg) => ApiError::Conflict(msg),
            ActionError::Validation(_) => ApiError::Internal("unexpected validation error".into()),
            ActionError::Db(e) => ApiError::Db(e),
        })?;
    }
    if let Some(m) = req.session_minutes {
        sqlx::query("UPDATE clubs SET session_minutes = $1 WHERE id = $2")
            .bind(m)
            .bind(club.id)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(d) = req.queue_depth {
        sqlx::query("UPDATE clubs SET queue_depth = $1 WHERE id = $2")
            .bind(d)
            .bind(club.id)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(a) = req.auto_extend {
        sqlx::query("UPDATE clubs SET auto_extend = $1 WHERE id = $2")
            .bind(a)
            .bind(club.id)
            .execute(&mut *tx)
            .await?;
    }
    for (t, col) in [(opens_at, "opens_at"), (closes_at, "closes_at")] {
        if let Some(t) = t {
            sqlx::query(&format!("UPDATE clubs SET {col} = $1 WHERE id = $2"))
                .bind(t)
                .bind(club.id)
                .execute(&mut *tx)
                .await?;
        }
    }
    if let Some(theme) = &req.kiosk_theme {
        sqlx::query("UPDATE clubs SET kiosk_theme = $1 WHERE id = $2")
            .bind(theme)
            .bind(club.id)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(color) = &req.brand_color {
        sqlx::query("UPDATE clubs SET brand_color = $1 WHERE id = $2")
            .bind(color)
            .bind(club.id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;

    state.notify_club(club.id);
    let club = courts::club_by_slug(&state.db, &slug).await?.ok_or(ApiError::NotFound)?;
    Ok(Json(ApiResponse::ok(club_json(&club))))
}

// ---- club admin: closures ---------------------------------------------------

#[derive(Deserialize)]
pub struct CloseCourtReq {
    pub reason: Option<String>,
}

/// Close a court: the running session plays out to its end, but no new groups
/// land on it, and its queue is released (players get redirected at the desk).
pub async fn admin_close_court(
    State(state): State<AppState>,
    Path((slug, number)): Path<(String, i32)>,
    token: ClubAdminToken,
    Json(req): Json<CloseCourtReq>,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    let club = require_club_admin(&state, &slug, &token).await?;
    reject_suspended(&club)?;
    let reason = req.reason.as_deref().map(str::trim).filter(|r| !r.is_empty());

    let mut tx = state.db.begin().await?;
    courts::lock_court(&mut tx, club.id, number).await?;
    let updated = sqlx::query(
        "UPDATE club_courts SET closed = TRUE, closed_reason = $1
         WHERE club_id = $2 AND number = $3",
    )
    .bind(reason)
    .bind(club.id)
    .bind(number)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    let released = sqlx::query("DELETE FROM court_queues WHERE club_id = $1 AND court_number = $2")
        .bind(club.id)
        .bind(number)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;

    state.notify_club(club.id);
    let msg = if released > 0 {
        format!(
            "Court {number} closed. {released} queued group(s) were released — \
             please redirect those players at the desk."
        )
    } else {
        format!("Court {number} closed. The current game will play out its timer.")
    };
    Ok(Json(ApiResponse::ok_msg(json!({ "released_groups": released }), msg)))
}

pub async fn admin_reopen_court(
    State(state): State<AppState>,
    Path((slug, number)): Path<(String, i32)>,
    token: ClubAdminToken,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    let club = require_club_admin(&state, &slug, &token).await?;
    reject_suspended(&club)?;
    // Same lock contract as close/take/expire: reopening must not race the
    // engine's closed-flag read at the expiry instant.
    let mut tx = state.db.begin().await?;
    courts::lock_court(&mut tx, club.id, number).await?;
    let updated = sqlx::query(
        "UPDATE club_courts SET closed = FALSE, closed_reason = NULL
         WHERE club_id = $1 AND number = $2",
    )
    .bind(club.id)
    .bind(number)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    tx.commit().await?;
    state.notify_club(club.id);
    Ok(Json(ApiResponse::message(format!("Court {number} reopened."))))
}

// ---- club admin: credentials ------------------------------------------------

/// Issue a fresh kiosk credential pair; the pair is shown once in the console
/// (and printed on a slip at the desk).
pub async fn admin_issue_credential(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    token: ClubAdminToken,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    let club = require_club_admin(&state, &slug, &token).await?;
    reject_suspended(&club)?;
    let password = courts::generate_password();
    // Regenerate on username collision (unique per club).
    for _ in 0..20 {
        let username = courts::generate_username();
        let inserted: Result<(Uuid, DateTime<Utc>), sqlx::Error> = sqlx::query_as(
            "INSERT INTO club_credentials (club_id, username, password)
             VALUES ($1, $2, $3) RETURNING id, issued_at",
        )
        .bind(club.id)
        .bind(&username)
        .bind(&password)
        .fetch_one(&state.db)
        .await;
        match inserted {
            Ok((id, issued_at)) => {
                return Ok(Json(ApiResponse::ok(json!({
                    "id": id,
                    "username": username,
                    "password": password,
                    "status": "active",
                    "issued_at": issued_at.to_rfc3339(),
                }))));
            }
            Err(sqlx::Error::Database(db)) if db.is_unique_violation() => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(ApiError::Internal("could not generate a unique username".into()))
}

#[derive(Deserialize)]
pub struct CredListQuery {
    pub today: Option<String>,
}

pub async fn admin_list_credentials(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(q): Query<CredListQuery>,
    token: ClubAdminToken,
) -> Result<Json<ApiResponse<Vec<Value>>>, ApiError> {
    let club = require_club_admin(&state, &slug, &token).await?;
    let today_only = q.today.as_deref() == Some("1");
    let since = if today_only { local_midnight_utc() } else { DateTime::<Utc>::MIN_UTC };

    type CredRow = (
        Uuid,
        String,
        String,
        String,
        DateTime<Utc>,
        Option<i32>,
        Option<i32>,
        Option<i32>,
    );
    let rows: Vec<CredRow> = sqlx::query_as(
        "SELECT c.id, c.username, c.password, c.status, c.issued_at,
                s.court_number, q.court_number, q.position
         FROM club_credentials c
         LEFT JOIN LATERAL (
             SELECT cs.court_number FROM session_players sp
             JOIN court_sessions cs ON cs.id = sp.session_id
             WHERE sp.credential_id = c.id AND cs.status = 'active' LIMIT 1
         ) s ON TRUE
         LEFT JOIN LATERAL (
             SELECT cq.court_number, cq.position FROM queue_players qp
             JOIN court_queues cq ON cq.id = qp.queue_id
             WHERE qp.credential_id = c.id LIMIT 1
         ) q ON TRUE
         WHERE c.club_id = $1 AND c.issued_at >= $2
         ORDER BY c.issued_at DESC",
    )
    .bind(club.id)
    .bind(since)
    .fetch_all(&state.db)
    .await?;

    let out = rows
        .into_iter()
        .map(|(id, username, password, status, issued_at, on_court, q_court, q_pos)| {
            let location = if let Some(court) = on_court {
                json!({ "kind": "court", "court_number": court, "position": null })
            } else if let Some(court) = q_court {
                json!({ "kind": "queue", "court_number": court, "position": q_pos })
            } else {
                json!({ "kind": null, "court_number": null, "position": null })
            };
            json!({
                "id": id,
                "username": username,
                "password": password,
                "status": status,
                "issued_at": issued_at.to_rfc3339(),
                "where": location,
            })
        })
        .collect();
    Ok(Json(ApiResponse::ok(out)))
}

/// Revoke a credential. It stays wherever it currently is (board unchanged);
/// the engine drops its queue group at promotion time per the expiry rules.
pub async fn admin_revoke_credential(
    State(state): State<AppState>,
    Path((slug, id)): Path<(String, Uuid)>,
    token: ClubAdminToken,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    let club = require_club_admin(&state, &slug, &token).await?;
    reject_suspended(&club)?;
    let mut tx = state.db.begin().await?;
    // If the credential sits in a queue, serialize with that court's promotion
    // path: without the lock, the engine could promote the group between its
    // revoked-members check and this UPDATE committing.
    let queued: Option<(i32,)> = sqlx::query_as(
        "SELECT q.court_number FROM queue_players qp
         JOIN court_queues q ON q.id = qp.queue_id
         WHERE qp.credential_id = $1 AND q.club_id = $2
         LIMIT 1",
    )
    .bind(id)
    .bind(club.id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((court_number,)) = queued {
        courts::lock_court(&mut tx, club.id, court_number).await?;
    }
    let updated = sqlx::query(
        "UPDATE club_credentials SET status = 'revoked' WHERE id = $1 AND club_id = $2",
    )
    .bind(id)
    .bind(club.id)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    tx.commit().await?;
    Ok(Json(ApiResponse::message("Credential revoked.")))
}

// ---- kiosk ------------------------------------------------------------------

pub async fn board(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    let club = kiosk_club(&state, &slug).await?;
    let board = courts::board_snapshot(&state.db, &club).await?;
    Ok(Json(ApiResponse::ok(board)))
}

/// Per-club board stream: an initial "board" event on connect, then a fresh
/// snapshot on every kiosk mutation / admin change / engine state change.
/// Mirrors the reservations SSE pattern, but fans out per club.
pub async fn board_stream(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> Result<
    (
        [(axum::http::HeaderName, &'static str); 1],
        Sse<impl Stream<Item = Result<Event, Infallible>>>,
    ),
    ApiError,
> {
    let club = kiosk_club(&state, &slug).await?;
    let mut rx = state.club_channel(club.id).subscribe();
    let db = state.db.clone();

    let stream = async_stream::stream! {
        loop {
            // Rebuild from scratch each push so config changes are reflected
            // and the stream can never drift from GET /board.
            match courts::club_by_slug(&db, &slug).await {
                Ok(Some(club)) if club.status != "suspended" => {
                    if let Ok(board) = courts::board_snapshot(&db, &club).await {
                        yield Ok(Event::default().event("board").data(board.to_string()));
                    }
                }
                _ => break, // club vanished or was suspended — end the stream
            }
            match rx.recv().await {
                Ok(()) => {}
                // Missed nudges just mean the next snapshot is extra fresh.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    // X-Accel-Buffering tells nginx (and friends) to flush each event through
    // per-response — without it a buffering proxy holds events back while the
    // connection still LOOKS healthy, silently freezing every kiosk. The club
    // slug is dynamic, so a per-location nginx override can't cover this.
    let no_buffer = [(axum::http::HeaderName::from_static("x-accel-buffering"), "no")];
    Ok((
        no_buffer,
        Sse::new(stream).keep_alive(
            KeepAlive::new()
                .interval(std::time::Duration::from_secs(15))
                .text("keep-alive"),
        ),
    ))
}

#[derive(Deserialize)]
pub struct KioskActionReq {
    pub court_number: i32,
    pub players: Vec<PlayerCred>,
}

/// Shared kiosk-action preamble: club must be visible, within opening hours,
/// and the court number on the board.
async fn kiosk_action_club(
    state: &AppState,
    slug: &str,
    court_number: i32,
) -> Result<ClubRow, ApiError> {
    let club = kiosk_club(state, slug).await?;
    if !club.open_now() {
        return Err(ApiError::BadRequest(format!(
            "The club is closed — courts can be taken {}–{}.",
            club.opens_at.format("%H:%M"),
            club.closes_at.format("%H:%M"),
        )));
    }
    if !(1..=club.court_count).contains(&court_number) {
        return Err(ApiError::BadRequest(format!(
            "Court number must be between 1 and {}.",
            club.court_count
        )));
    }
    Ok(club)
}

/// Per-username password-guess lockout: refuse the whole action when any
/// submitted username is locked, with a generic message that reveals nothing
/// about the username or password.
async fn check_kiosk_lockouts(
    state: &AppState,
    club_id: Uuid,
    players: &[PlayerCred],
) -> Result<(), ApiError> {
    // Shape check FIRST: this runs before any other validation and each
    // username costs a Redis lookup, so an oversized unauthenticated body
    // must not be able to farm per-entry work.
    if !(players.len() == 2 || players.len() == 4)
        || players.iter().any(|p| p.username.len() > 64)
    {
        return Err(ApiError::BadRequest("Enter the logins for 2 or 4 players.".into()));
    }
    for p in players {
        if otp::is_kiosk_username_locked(state.redis.clone(), club_id, &p.username).await {
            return Err(ApiError::RateLimited(
                "Too many failed attempts. Please try again later or see the front desk.".into(),
            ));
        }
    }
    Ok(())
}

/// Count each wrong-password refusal toward its username's lockout.
async fn note_kiosk_failures<T>(
    state: &AppState,
    club_id: Uuid,
    result: &Result<T, ActionError>,
) {
    if let Err(ActionError::Validation(errors)) = result {
        for e in errors.iter().filter(|e| e.code == "bad_password") {
            if otp::note_kiosk_bad_password(state.redis.clone(), club_id, &e.username).await {
                tracing::warn!(club_id = %club_id, username = %e.username, "kiosk username locked after repeated bad passwords");
                crate::metrics::record_feature("kiosk_username_locked", "web");
            }
        }
    }
}

/// Map a domain refusal onto the wire: per-credential errors keep the
/// success:false envelope with data.errors so the kiosk can mark each field.
fn action_response(result: Result<Value, ActionError>, ok_message: &str) -> Result<Response, ApiError> {
    match result {
        Ok(data) => Ok(Json(ApiResponse::ok_msg(data, ok_message)).into_response()),
        Err(ActionError::Validation(errors)) => Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "data": { "errors": errors },
                "message": "Check the highlighted logins and try again.",
            })),
        )
            .into_response()),
        Err(ActionError::Court(msg)) => Err(ApiError::Conflict(msg)),
        Err(ActionError::Db(e)) => Err(ApiError::Db(e)),
    }
}

pub async fn kiosk_take(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Json(req): Json<KioskActionReq>,
) -> Result<Response, ApiError> {
    let club = kiosk_action_club(&state, &slug, req.court_number).await?;
    check_kiosk_lockouts(&state, club.id, &req.players).await?;
    let result = courts::take_court(&state.db, &club, req.court_number, &req.players)
        .await
        .map(|()| json!({ "court_number": req.court_number }));
    note_kiosk_failures(&state, club.id, &result).await;
    if result.is_ok() {
        state.notify_club(club.id);
    }
    action_response(result, &format!("Court {} is yours — play on!", req.court_number))
}

pub async fn kiosk_join(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Json(req): Json<KioskActionReq>,
) -> Result<Response, ApiError> {
    let club = kiosk_action_club(&state, &slug, req.court_number).await?;
    check_kiosk_lockouts(&state, club.id, &req.players).await?;
    let result = courts::join_court(&state.db, &club, req.court_number, &req.players)
        .await
        .map(|()| json!({ "court_number": req.court_number }));
    note_kiosk_failures(&state, club.id, &result).await;
    if result.is_ok() {
        state.notify_club(club.id);
    }
    action_response(result, &format!("You're in on court {}.", req.court_number))
}

pub async fn kiosk_queue(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Json(req): Json<KioskActionReq>,
) -> Result<Response, ApiError> {
    let club = kiosk_action_club(&state, &slug, req.court_number).await?;
    check_kiosk_lockouts(&state, club.id, &req.players).await?;
    let result = courts::queue_court(&state.db, &club, req.court_number, &req.players)
        .await
        .map(|position| json!({ "court_number": req.court_number, "position": position }));
    note_kiosk_failures(&state, club.id, &result).await;
    if result.is_ok() {
        state.notify_club(club.id);
    }
    action_response(
        result,
        &format!("You're queued for court {}.", req.court_number),
    )
}

// ---- tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hours_window_rejects_closes_at_not_after_opens_at() {
        let t = |s: &str| time::parse_hhmm(s).unwrap();
        // Valid same-day window.
        assert!(hours_valid(t("06:00"), t("22:00")));
        // Equal or inverted (overnight) windows are rejected — they would
        // make open_now() permanently false.
        assert!(!hours_valid(t("18:00"), t("18:00")));
        assert!(!hours_valid(t("18:00"), t("01:00")));
    }
}
