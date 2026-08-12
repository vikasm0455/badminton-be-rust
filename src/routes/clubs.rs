//! Courts v1 HTTP surface: platform console (OTP-gated), club-admin console
//! (argon2 password login), and the public kiosk endpoints. All domain
//! mutations live in crate::courts — this module is auth, envelopes, and the
//! open-hours gate.

use std::convert::Infallible;

use axum::Json;
use axum::async_trait;
use axum::extract::{FromRequestParts, Path, State};
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
        "timezone": club.timezone,
        "created_at": club.created_at.to_rfc3339(),
    })
}

/// v2 court cap (config + platform create).
const MAX_COURTS: i32 = 100;

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
    pub timezone: Option<String>,
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
    if !(1..=MAX_COURTS).contains(&req.court_count) {
        return Err(ApiError::BadRequest(format!(
            "court count must be between 1 and {MAX_COURTS}"
        )));
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
    // Day passes hinge on the club's "today", so the timezone must be a real
    // IANA name chrono-tz can resolve — validated with the SAME parser the
    // runtime uses.
    let timezone = req.timezone.unwrap_or_else(|| "America/Los_Angeles".to_string());
    if courts::parse_timezone(&timezone).is_none() {
        return Err(ApiError::BadRequest(
            "timezone must be a valid IANA name like America/Los_Angeles".into(),
        ));
    }

    let temp_password = courts::generate_admin_password();
    let password_hash = hash_password(&temp_password)?;

    let mut tx = state.db.begin().await?;
    let club: Result<ClubRow, sqlx::Error> = sqlx::query_as(&format!(
        "INSERT INTO clubs (slug, name, brand_color, court_count, session_minutes, queue_depth, timezone)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING {}",
        courts::CLUB_COLUMNS
    ))
    .bind(&slug)
    .bind(&name)
    .bind(&brand_color)
    .bind(req.court_count)
    .bind(session_minutes)
    .bind(queue_depth)
    .bind(timezone.trim())
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

/// Slug-less club-admin sign-in for the marketing landing's "Club admin
/// sign-in" door: the admin gives only their email + password, and we resolve
/// which club they run (club_admins.email is globally UNIQUE, so one email
/// maps to exactly one admin/club). Mirrors admin_login's lockout + argon2
/// timing-safety, keyed on the email alone.
pub async fn admin_login_by_email(
    State(state): State<AppState>,
    Json(req): Json<AdminLoginReq>,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    let email = req.email.trim().to_lowercase();
    let lock_scope = format!("club-admin-email:{email}");
    if otp::is_account_locked(&state, &lock_scope).await {
        return Err(ApiError::RateLimited(
            "Too many failed sign-ins. Please try again later.".into(),
        ));
    }
    let row: Option<(Uuid, String, String, bool, String, String)> = sqlx::query_as(
        "SELECT a.id, a.name, a.password_hash, a.must_change, c.slug, c.name
         FROM club_admins a JOIN clubs c ON c.id = a.club_id
         WHERE LOWER(a.email) = $1",
    )
    .bind(&email)
    .fetch_optional(&state.db)
    .await?;
    let bad = || ApiError::BadRequest("Incorrect email or password.".into());
    let Some((id, name, hash, must_change, slug, club_name)) = row else {
        // Burn the same argon2 time as a real verification so response timing
        // can't enumerate admin emails.
        verify_password(req.password.trim(), dummy_hash());
        otp::note_login_failure(&state, &lock_scope).await;
        return Err(bad());
    };
    if !verify_password(req.password.trim(), &hash) {
        otp::note_login_failure(&state, &lock_scope).await;
        return Err(bad());
    }
    let token = issue_token_for(id, "club_admin", &state.config.jwt_secret, COURTS_TOKEN_DAYS)?;
    Ok(Json(ApiResponse::ok(json!({
        "token": token,
        "must_change": must_change,
        "name": name,
        "email": email,
        "club": { "slug": slug, "name": club_name },
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
    // "Today" is the club's calendar day — the same day passes are keyed by.
    let (credentials_today,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM club_credentials WHERE club_id = $1 AND valid_date = $2",
    )
    .bind(club.id)
    .bind(club.today())
    .fetch_one(&state.db)
    .await?;
    let courts: Vec<(i32, bool, Option<String>, Option<DateTime<Utc>>, Option<DateTime<Utc>>)> =
        sqlx::query_as(&format!(
            "SELECT number, {}, closed_reason, closed_from, closed_until
             FROM club_courts WHERE club_id = $1 ORDER BY number",
            courts::COURT_CLOSED_SQL
        ))
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
            .map(|(number, closed, closed_reason, closed_from, closed_until)| json!({
                "number": number,
                "closed": closed,
                "closed_reason": closed_reason,
                "closed_from": closed_from.map(|t| t.to_rfc3339()),
                "closed_until": closed_until.map(|t| t.to_rfc3339()),
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
    pub timezone: Option<String>,
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
        if !(1..=MAX_COURTS).contains(&n) {
            return Err(ApiError::BadRequest(format!(
                "court count must be between 1 and {MAX_COURTS}"
            )));
        }
    }
    if let Some(tz) = &req.timezone {
        if courts::parse_timezone(tz).is_none() {
            return Err(ApiError::BadRequest(
                "timezone must be a valid IANA name like America/Los_Angeles".into(),
            ));
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
    if let Some(tz) = &req.timezone {
        sqlx::query("UPDATE clubs SET timezone = $1 WHERE id = $2")
            .bind(tz.trim())
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
    pub reason: String,
    /// Optional start; defaults to now. Accepts RFC3339, "YYYY-MM-DDTHH:MM"
    /// (club-local), or "HH:MM" (today, club-local — the admin modal's shape).
    pub from: Option<String>,
    /// Required end of the window, same formats.
    pub until: String,
}

/// Parse a closure instant: RFC3339 with offset, else a club-local datetime,
/// else a club-local wall-clock time meaning "today".
fn parse_close_instant(raw: &str, club: &ClubRow) -> Option<DateTime<Utc>> {
    let raw = raw.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Some(dt.with_timezone(&Utc));
    }
    let local = if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M") {
        naive
    } else {
        club.today().and_time(time::parse_hhmm(raw)?)
    };
    use chrono::TimeZone;
    match club.tz().from_local_datetime(&local) {
        chrono::LocalResult::Single(dt) | chrono::LocalResult::Ambiguous(dt, _) => {
            Some(dt.with_timezone(&Utc))
        }
        chrono::LocalResult::None => None,
    }
}

/// Close a court for a timed window (v2): custom reason + from/until. The
/// running session plays out to its end, but no new groups land on it, its
/// queue is released, and the court reopens ITSELF when the window ends (the
/// engine broadcasts at both boundaries).
pub async fn admin_close_court(
    State(state): State<AppState>,
    Path((slug, number)): Path<(String, i32)>,
    token: ClubAdminToken,
    Json(req): Json<CloseCourtReq>,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    let club = require_club_admin(&state, &slug, &token).await?;
    reject_suspended(&club)?;
    // Strip ASCII control chars (defense-in-depth for the public board — the
    // FE escapes, but stored text should never carry \n, \r or ESC anyway).
    let reason: String = req.reason.chars().filter(|c| !c.is_ascii_control()).collect();
    let reason = reason.trim();
    if reason.is_empty() || reason.chars().count() > 80 {
        return Err(ApiError::BadRequest(
            "A short reason (shown to players) is required.".into(),
        ));
    }
    // DB clock, not the app clock: the immediate-vs-boundary release decision
    // below must share a clock with COURT_CLOSED_SQL and the engine's
    // watermarks, or a window whose `from` lands inside the skew is future
    // per the app yet already past the engine's watermark — released by
    // neither side, stranding the queue.
    let now = courts::db_now(&state.db).await?;
    let from = match &req.from {
        Some(raw) if !raw.trim().is_empty() => parse_close_instant(raw, &club)
            .ok_or_else(|| ApiError::BadRequest("Couldn't read the closure start time.".into()))?,
        _ => now,
    };
    let until = parse_close_instant(&req.until, &club)
        .ok_or_else(|| ApiError::BadRequest("Couldn't read the closure end time.".into()))?;
    courts::valid_close_window(from, until, now)
        .map_err(|msg| ApiError::BadRequest(msg.into()))?;

    let mut tx = state.db.begin().await?;
    courts::lock_court(&mut tx, club.id, number).await?;
    // The legacy bool is force-cleared: the window IS the closed state now.
    let updated = sqlx::query(
        "UPDATE club_courts
         SET closed = FALSE, closed_reason = $1, closed_from = $2, closed_until = $3
         WHERE club_id = $4 AND number = $5",
    )
    .bind(reason)
    .bind(from)
    .bind(until)
    .bind(club.id)
    .bind(number)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    // Release the queue only when the closure starts NOW. A future-dated
    // window keeps its queue promotable until the window actually begins —
    // the engine's closure_boundary_pass releases it at the start boundary,
    // so no group is stranded on a session-less closed court either way.
    let released = if from <= now {
        sqlx::query("DELETE FROM court_queues WHERE club_id = $1 AND court_number = $2")
            .bind(club.id)
            .bind(number)
            .execute(&mut *tx)
            .await?
            .rows_affected()
    } else {
        0
    };
    tx.commit().await?;

    state.notify_club(club.id);
    // tz-aware display string for the confirmation toast.
    let until_display = until.with_timezone(&club.tz()).format("%H:%M").to_string();
    let msg = if released > 0 {
        format!(
            "Court {number} closed until {until_display}. {released} queued group(s) were \
             released — please redirect those players at the desk."
        )
    } else if from > now {
        let from_display = from.with_timezone(&club.tz()).format("%H:%M").to_string();
        format!(
            "Court {number} closes {from_display}–{until_display}. Any queue is released \
             when the closure starts; it reopens automatically."
        )
    } else {
        format!("Court {number} closed until {until_display}. It reopens automatically.")
    };
    Ok(Json(ApiResponse::ok_msg(
        json!({
            "released_groups": released,
            "closed_from": from.to_rfc3339(),
            "closed_until": until.to_rfc3339(),
        }),
        msg,
    )))
}

/// Reopen clears the whole closed state early: window, reason, and the legacy
/// manual bool.
pub async fn admin_reopen_court(
    State(state): State<AppState>,
    Path((slug, number)): Path<(String, i32)>,
    token: ClubAdminToken,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    let club = require_club_admin(&state, &slug, &token).await?;
    reject_suspended(&club)?;
    // Same lock contract as close/take/expire: reopening must not race the
    // engine's closed-state read at the expiry instant.
    let mut tx = state.db.begin().await?;
    courts::lock_court(&mut tx, club.id, number).await?;
    let updated = sqlx::query(
        "UPDATE club_courts
         SET closed = FALSE, closed_reason = NULL, closed_from = NULL, closed_until = NULL
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

// ---- club admin: today's logins ----------------------------------------------
//
// v1's staff-issued credential endpoint is GONE (players self-serve at the
// stations now); staff instead get a read of TODAY's logins with the passwords
// visible — the desk reads a forgotten password back to a player, same trust
// level as the paper slip it replaces.

pub async fn admin_list_credentials(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    token: ClubAdminToken,
) -> Result<Json<ApiResponse<Vec<Value>>>, ApiError> {
    let club = require_club_admin(&state, &slug, &token).await?;

    type CredRow = (
        Uuid,
        String,
        String,
        String,
        String,
        Option<String>,
        DateTime<Utc>,
        Option<i32>,
        Option<i32>,
        Option<i32>,
    );
    let rows: Vec<CredRow> = sqlx::query_as(
        "SELECT c.id, c.username, c.password, c.status, c.kind,
                COALESCE(m.display_name, m.username) AS member_name, c.issued_at,
                s.court_number, q.court_number, q.position
         FROM club_credentials c
         LEFT JOIN club_members m ON m.id = c.member_id AND m.club_id = c.club_id
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
         WHERE c.club_id = $1 AND c.valid_date = $2
         ORDER BY c.issued_at DESC",
    )
    .bind(club.id)
    .bind(club.today())
    .fetch_all(&state.db)
    .await?;

    let out = rows
        .into_iter()
        .map(
            |(id, username, password, status, kind, member_name, issued_at, on_court, q_court, q_pos)| {
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
                    "kind": kind,
                    "member_name": member_name,
                    "issued_at": issued_at.to_rfc3339(),
                    "where": location,
                })
            },
        )
        .collect();
    Ok(Json(ApiResponse::ok(out)))
}

// ---- club admin: members ------------------------------------------------------

pub async fn admin_list_members(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    token: ClubAdminToken,
) -> Result<Json<ApiResponse<Vec<Value>>>, ApiError> {
    let club = require_club_admin(&state, &slug, &token).await?;
    let rows: Vec<(Uuid, String, String, Option<String>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, member_ref, username, display_name, created_at
         FROM club_members WHERE club_id = $1 AND status = 'active'
         ORDER BY created_at DESC",
    )
    .bind(club.id)
    .fetch_all(&state.db)
    .await?;
    let out = rows
        .into_iter()
        .map(|(id, member_ref, username, display_name, created_at)| {
            json!({
                "id": id,
                "member_ref": member_ref,
                "username": username,
                "display_name": display_name,
                "created_at": created_at.to_rfc3339(),
            })
        })
        .collect();
    Ok(Json(ApiResponse::ok(out)))
}

#[derive(Deserialize)]
pub struct AddMemberReq {
    pub member_ref: String,
    pub username: String,
    pub display_name: Option<String>,
}

/// Add a member: link their existing card (member_ref — what the barcode
/// encodes) to a permanent kiosk username.
pub async fn admin_add_member(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    token: ClubAdminToken,
    Json(req): Json<AddMemberReq>,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    let club = require_club_admin(&state, &slug, &token).await?;
    reject_suspended(&club)?;
    let member_ref = req.member_ref.trim().to_string();
    if member_ref.is_empty() || member_ref.chars().count() > 64 {
        return Err(ApiError::BadRequest("Member ID must be 1–64 characters.".into()));
    }
    let username = req.username.trim().to_lowercase();
    if !courts::valid_kiosk_username(&username) {
        return Err(ApiError::BadRequest(
            "Username must be 3–20 characters of a-z, 0-9, dot, dash or underscore.".into(),
        ));
    }
    let display_name = req
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_string);
    if display_name.as_deref().is_some_and(|n| n.chars().count() > 60) {
        return Err(ApiError::BadRequest("Display name must be at most 60 characters.".into()));
    }
    // Serialize with walkin_create on the (club, username) advisory lock —
    // this is the other half of the cross-table check-then-insert pair (we
    // check club_credentials then insert club_members; the walk-in station
    // checks club_members then inserts club_credentials). This lock is the
    // ONLY advisory lock this path takes (see courts::lock_username's global
    // lock-order note).
    let mut tx = state.db.begin().await?;
    courts::lock_username(&mut tx, club.id, &username).await?;
    // A walk-in already holds this username TODAY: adding the member now would
    // brick their first check-in (today's credential slot is taken).
    let taken_today: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM club_credentials
         WHERE club_id = $1 AND username = $2 AND valid_date = $3",
    )
    .bind(club.id)
    .bind(&username)
    .bind(club.today())
    .fetch_one(&mut *tx)
    .await?;
    if taken_today > 0 {
        return Err(ApiError::Conflict(format!(
            "A walk-in is using \"{username}\" today — it frees up at midnight; \
             pick another username or add the member tomorrow."
        )));
    }

    let inserted: Result<(Uuid, DateTime<Utc>), sqlx::Error> = sqlx::query_as(
        "INSERT INTO club_members (club_id, member_ref, username, display_name)
         VALUES ($1, $2, $3, $4) RETURNING id, created_at",
    )
    .bind(club.id)
    .bind(&member_ref)
    .bind(&username)
    .bind(&display_name)
    .fetch_one(&mut *tx)
    .await;
    let (id, created_at) = inserted.map_err(|e| match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            // Two partial unique indexes — tell the admin which field clashed.
            if db.constraint() == Some("club_members_ref_active") {
                ApiError::Conflict(format!("Member ID \"{member_ref}\" is already registered."))
            } else {
                ApiError::Conflict(format!("Username \"{username}\" already belongs to a member."))
            }
        }
        _ => ApiError::Db(e),
    })?;
    tx.commit().await?;
    Ok(Json(ApiResponse::ok_msg(
        json!({
            "id": id,
            "member_ref": member_ref,
            "username": username,
            "display_name": display_name,
            "created_at": created_at.to_rfc3339(),
        }),
        "Member added.",
    )))
}

/// Remove a member (soft): the card + username free up for reuse from
/// TOMORROW; today's credential (if they checked in) is revoked immediately.
pub async fn admin_remove_member(
    State(state): State<AppState>,
    Path((slug, id)): Path<(String, Uuid)>,
    token: ClubAdminToken,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    let club = require_club_admin(&state, &slug, &token).await?;
    reject_suspended(&club)?;
    let mut tx = state.db.begin().await?;
    let updated = sqlx::query(
        "UPDATE club_members SET status = 'removed'
         WHERE id = $1 AND club_id = $2 AND status = 'active'",
    )
    .bind(id)
    .bind(club.id)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    // Revoke today's pass. If it sits in a queue OR an active session,
    // serialize with that court first — same lock rule as
    // admin_revoke_credential.
    let today_cred: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM club_credentials
         WHERE club_id = $1 AND member_id = $2 AND valid_date = $3 AND status = 'active'",
    )
    .bind(club.id)
    .bind(id)
    .bind(club.today())
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((cred_id,)) = today_cred {
        lock_placement_courts(&mut tx, club.id, cred_id).await?;
        sqlx::query("UPDATE club_credentials SET status = 'revoked' WHERE id = $1")
            .bind(cred_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(Json(ApiResponse::message(
        "Member removed. Their card and username free up tomorrow; today's pass is revoked.",
    )))
}

/// Advisory-lock every court the credential is currently placed on (queue
/// AND/OR active session), ascending, before a status UPDATE. Queue: without
/// the lock the engine could promote the group between its revoked-members
/// check and the UPDATE committing. Session: without it a revoke committing
/// between expire_court's session-players validity read and its commit lets a
/// just-revoked group receive one full auto-extension. Ascending order keeps
/// the global court-lock order acyclic if both somehow apply.
async fn lock_placement_courts(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    club_id: Uuid,
    cred_id: Uuid,
) -> Result<(), sqlx::Error> {
    let mut courts_to_lock: Vec<i32> = Vec::new();
    let queued: Option<(i32,)> = sqlx::query_as(
        "SELECT q.court_number FROM queue_players qp
         JOIN court_queues q ON q.id = qp.queue_id
         WHERE qp.credential_id = $1 AND q.club_id = $2
         LIMIT 1",
    )
    .bind(cred_id)
    .bind(club_id)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some((court_number,)) = queued {
        courts_to_lock.push(court_number);
    }
    let in_session: Option<(i32,)> = sqlx::query_as(
        "SELECT cs.court_number FROM session_players sp
         JOIN court_sessions cs ON cs.id = sp.session_id
         WHERE sp.credential_id = $1 AND cs.club_id = $2 AND cs.status = 'active'
         LIMIT 1",
    )
    .bind(cred_id)
    .bind(club_id)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some((court_number,)) = in_session {
        courts_to_lock.push(court_number);
    }
    courts_to_lock.sort_unstable();
    courts_to_lock.dedup();
    for court_number in courts_to_lock {
        courts::lock_court(tx, club_id, court_number).await?;
    }
    Ok(())
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
    // Serialize with the engine on any court this credential currently
    // occupies (queue promotion AND session auto-extend both read validity).
    lock_placement_courts(&mut tx, club.id, id).await?;
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

// ---- kiosk: unsign (leave court / leave queue) --------------------------------
//
// Deliberately NOT gated on opening hours: players must always be able to sign
// out (the engine keeps promoting after close for the same reason). The
// password lockout still applies — these endpoints verify credentials too.

pub async fn kiosk_leave(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Json(req): Json<KioskActionReq>,
) -> Result<Response, ApiError> {
    let club = kiosk_club(&state, &slug).await?;
    if !(1..=club.court_count).contains(&req.court_number) {
        return Err(ApiError::BadRequest(format!(
            "Court number must be between 1 and {}.",
            club.court_count
        )));
    }
    check_kiosk_lockouts(&state, club.id, &req.players).await?;
    let result = courts::leave_court(&state.db, &club, req.court_number, &req.players)
        .await
        .map(|o| {
            json!({
                "court_number": req.court_number,
                "session_ended": o.session_ended,
                "promoted": o.promoted,
            })
        });
    note_kiosk_failures(&state, club.id, &result).await;
    if result.is_ok() {
        state.notify_club(club.id);
    }
    action_response(
        result,
        &format!("You're signed off court {} — thanks for playing!", req.court_number),
    )
}

pub async fn kiosk_queue_leave(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Json(req): Json<KioskActionReq>,
) -> Result<Response, ApiError> {
    let club = kiosk_club(&state, &slug).await?;
    if !(1..=club.court_count).contains(&req.court_number) {
        return Err(ApiError::BadRequest(format!(
            "Court number must be between 1 and {}.",
            club.court_count
        )));
    }
    check_kiosk_lockouts(&state, club.id, &req.players).await?;
    let result = courts::leave_queue(&state.db, &club, req.court_number, &req.players)
        .await
        .map(|removed_group| {
            json!({ "court_number": req.court_number, "removed_group": removed_group })
        });
    note_kiosk_failures(&state, club.id, &result).await;
    if result.is_ok() {
        state.notify_club(club.id);
    }
    action_response(
        result,
        &format!("You've left the queue for court {}.", req.court_number),
    )
}

// ---- walk-in signup station ---------------------------------------------------

#[derive(Deserialize)]
pub struct WalkinReq {
    pub username: String,
}

/// Live availability probe for the walk-in station (no side effects). The
/// light per-IP cap keeps it from doubling as an unmetered member-username
/// oracle.
pub async fn walkin_check(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    ClientIp(ip): ClientIp,
    Json(req): Json<WalkinReq>,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    let club = kiosk_club(&state, &slug).await?;
    let username = req.username.trim().to_lowercase();
    if username.chars().count() > 64 {
        return Err(ApiError::BadRequest("Username is too long.".into()));
    }
    otp::check_walkin_probe_cap(&state, club.id, ip).await?;
    let reason = courts::walkin_unavailable_reason(&state.db, &club, &username).await?;
    Ok(Json(ApiResponse::ok(match reason {
        None => json!({ "available": true }),
        Some(reason) => json!({ "available": false, "reason": reason }),
    })))
}

/// Claim a walk-in username for today; the station shows the generated
/// password big. Per-IP creation cap prevents namespace squatting.
pub async fn walkin_create(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    ClientIp(ip): ClientIp,
    Json(req): Json<WalkinReq>,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    let club = kiosk_club(&state, &slug).await?;
    if !club.open_now() {
        return Err(ApiError::BadRequest(format!(
            "The club is closed — signups open {}–{}.",
            club.opens_at.format("%H:%M"),
            club.closes_at.format("%H:%M"),
        )));
    }
    let username = req.username.trim().to_lowercase();
    if username.chars().count() > 64 {
        return Err(ApiError::BadRequest("Username is too long.".into()));
    }
    otp::check_walkin_create_cap(&state, club.id, ip).await?;
    match courts::walkin_create(&state.db, &club, &username).await {
        Ok(password) => Ok(Json(ApiResponse::ok_msg(
            json!({ "username": username, "password": password }),
            "You're signed up for today — grab a court on the board!",
        ))),
        Err(courts::WalkinError::Unavailable("invalid")) => Err(ApiError::BadRequest(
            "Username must be 3–20 characters of a-z, 0-9, dot, dash or underscore.".into(),
        )),
        Err(courts::WalkinError::Unavailable(_)) => Err(ApiError::Conflict(format!(
            "\"{username}\" is taken today — try another username."
        ))),
        Err(courts::WalkinError::Db(e)) => Err(ApiError::Db(e)),
    }
}

// ---- member check-in station --------------------------------------------------

#[derive(Deserialize)]
pub struct CheckinReq {
    pub member_ref: String,
}

/// Member check-in: scan/type the member card ID, get the permanent username +
/// today's password (same password all day, fresh one tomorrow).
pub async fn member_checkin(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    ClientIp(ip): ClientIp,
    Json(req): Json<CheckinReq>,
) -> Result<Json<ApiResponse<Value>>, ApiError> {
    let club = kiosk_club(&state, &slug).await?;
    if !club.open_now() {
        return Err(ApiError::BadRequest(format!(
            "The club is closed — check-in opens {}–{}.",
            club.opens_at.format("%H:%M"),
            club.closes_at.format("%H:%M"),
        )));
    }
    let member_ref = req.member_ref.trim().to_string();
    if member_ref.is_empty() || member_ref.chars().count() > 64 {
        return Err(ApiError::BadRequest("Scan your card or type your member ID.".into()));
    }
    // Sliding cap on ALL check-in attempts (valid or not): a VALID member_ref
    // returns today's password, so without this a station IP could walk a
    // dense card-number space and harvest real credentials without ever
    // tripping the unknown-ref lockout below. Fail-open like the other
    // request limiters — the unknown-ref lockout stays fail-closed.
    otp::check_checkin_attempt_cap(&state, club.id, ip).await?;
    // Unknown-ref lockout, mirroring the kiosk password lockout (member IDs
    // are guessable card numbers — enumeration gets cut off, real members see
    // a generic message that reveals nothing).
    if otp::is_checkin_locked(state.redis.clone(), club.id, ip).await {
        return Err(ApiError::RateLimited(
            "Too many attempts. Please try again later or see the front desk.".into(),
        ));
    }
    match courts::member_checkin(&state.db, &club, &member_ref).await {
        Ok(res) => Ok(Json(ApiResponse::ok(json!({
            "display_name": res.display_name,
            "member_ref": res.member_ref,
            "username": res.username,
            "password": res.password,
        })))),
        Err(courts::CheckinError::UnknownMember) => {
            if otp::note_checkin_unknown_ref(state.redis.clone(), club.id, ip).await {
                tracing::warn!(club_id = %club.id, %ip, "check-in station locked after repeated unknown member IDs");
                crate::metrics::record_feature("checkin_station_locked", "web");
            }
            Err(ApiError::BadRequest(
                "We couldn't find that member ID. Check the card, or see the front desk.".into(),
            ))
        }
        Err(courts::CheckinError::Revoked) => Err(ApiError::Conflict(
            "Today's pass for this membership was cancelled — please see the front desk.".into(),
        )),
        Err(courts::CheckinError::UsernameHeld) => Err(ApiError::Conflict(
            "That username is held by a walk-in today — see the front desk.".into(),
        )),
        Err(courts::CheckinError::Db(e)) => Err(ApiError::Db(e)),
    }
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
