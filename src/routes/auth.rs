use axum::Json;
use axum::extract::State;
use axum::http::HeaderName;
use axum::http::header::SET_COOKIE;
use axum::response::AppendHeaders;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::{SessionUser, auth_cookie, clear_auth_cookie, issue_token, revoke_jti};
use crate::error::ApiError;
use crate::models::{ApiResponse, MeProfile};
use crate::net::ClientIp;
use crate::otp::{self, OtpPurpose, VerifyResult};
use crate::security::{self, event};
use crate::state::AppState;
use crate::{email, notify};

const MAX_EMAIL_LEN: usize = 254;
const INVALID_INVITE_DELAY_MS: u64 = 200;

type CookieResp<T> = (AppendHeaders<[(HeaderName, String); 1]>, Json<ApiResponse<T>>);

fn normalize_email(raw: &str) -> String {
    raw.trim().to_lowercase()
}

fn valid_email(email: &str) -> bool {
    email.contains('@') && email.len() >= 5 && email.len() <= MAX_EMAIL_LEN
}

fn valid_display_name(name: &str) -> bool {
    let len = name.chars().count();
    len >= 2 && len <= 30 && name.chars().all(|c| c.is_alphanumeric() || c == ' ')
}

// ---- invite validation -----------------------------------------------------

#[derive(Deserialize)]
pub struct ValidateInviteReq {
    pub code: String,
}

/// Returns 200 if the code is usable, 400 otherwise — without revealing *why*
/// (PRD §4.1.3, anti-enumeration), plus a constant ~200ms delay on failure.
pub async fn validate_invite(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<ValidateInviteReq>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    otp::check_invite_attempt(&state, ip).await?;
    let code = req.code.trim();

    let ok = invite_is_usable(&state, code).await?;
    if !ok {
        security::log(
            &state,
            event::INVALID_INVITE_ATTEMPT,
            None,
            Some(ip),
            json!({ "code_len": code.len() }),
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(INVALID_INVITE_DELAY_MS)).await;
        return Err(ApiError::BadRequest(
            "This invite link is invalid or has expired. Ask the admin for a new one.".into(),
        ));
    }
    Ok(Json(ApiResponse::ok(json!({ "valid": true }))))
}

async fn invite_is_usable(state: &AppState, code: &str) -> Result<bool, ApiError> {
    if code.len() != 12 || !code.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Ok(false);
    }
    let row: Option<(Option<Uuid>, Option<chrono::DateTime<chrono::Utc>>, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as(
            "SELECT used_by, revoked_at, expires_at FROM invite_codes WHERE LOWER(code) = LOWER($1)",
        )
        .bind(code)
        .fetch_optional(&state.db)
        .await?;
    let Some((used_by, revoked_at, expires_at)) = row else {
        return Ok(false);
    };
    Ok(used_by.is_none() && revoked_at.is_none() && expires_at > crate::time::now())
}

// ---- signup ----------------------------------------------------------------

#[derive(Deserialize)]
pub struct SignupReq {
    pub code: String,
    pub display_name: String,
    pub email: String,
}

#[derive(Serialize)]
pub struct VerificationPending {
    pub email: String,
    pub expires_in_minutes: i64,
    /// "email" in prod, "server-log" in dev (no RESEND_API_KEY).
    pub delivery: &'static str,
    pub resend_after_secs: i64,
}

pub async fn signup(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<SignupReq>,
) -> Result<Json<ApiResponse<VerificationPending>>, ApiError> {
    let email = normalize_email(&req.email);
    let display_name = req.display_name.trim().to_string();
    let code = req.code.trim().to_string();

    if !valid_email(&email) {
        return Err(ApiError::BadRequest("a valid email is required".into()));
    }
    if !valid_display_name(&display_name) {
        return Err(ApiError::BadRequest(
            "display name must be 2–30 letters, numbers or spaces".into(),
        ));
    }
    otp::check_invite_attempt(&state, ip).await?;
    if !invite_is_usable(&state, &code).await? {
        tokio::time::sleep(std::time::Duration::from_millis(INVALID_INVITE_DELAY_MS)).await;
        return Err(ApiError::BadRequest(
            "This invite link is invalid or has expired. Ask the admin for a new one.".into(),
        ));
    }

    // Existing email → tell them to log in. No OTP, invite not consumed.
    let exists: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM users WHERE LOWER(email) = $1")
            .bind(&email)
            .fetch_optional(&state.db)
            .await?;
    if exists.is_some() {
        return Err(ApiError::Conflict(
            "An account with this email already exists. Please log in.".into(),
        ));
    }

    otp::check_request_limits(&state, &email, ip).await?;
    let (code_value, resend_after) = otp::store_code(&state, OtpPurpose::Signup, &email).await?;

    // Stash the pending signup so /signup/verify can create the account.
    if let Some(mut r) = state.redis.clone() {
        let stash = json!({ "code": code, "display_name": display_name }).to_string();
        let _: Result<(), _> = r
            .set_ex(format!("pending_signup:{email}"), stash, otp::OTP_TTL_SECS as u64)
            .await;
    }

    if resend_after == 0 {
        email::send_otp(&state, &email, &code_value).await.ok();
    }
    security::log(&state, event::SIGNUP_ATTEMPTED, None, Some(ip), json!({ "email": email })).await;
    security::log(&state, event::OTP_ISSUED, None, Some(ip), json!({ "email": email, "purpose": "signup" })).await;

    Ok(Json(ApiResponse::ok(VerificationPending {
        email,
        expires_in_minutes: otp::OTP_TTL_SECS / 60,
        delivery: if state.config.resend_api_key.is_some() { "email" } else { "server-log" },
        resend_after_secs: resend_after,
    })))
}

#[derive(Deserialize)]
pub struct VerifyReq {
    pub email: String,
    pub code: String,
}

#[derive(Serialize)]
pub struct SignupVerified {
    pub status: String,
}

pub async fn signup_verify(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<VerifyReq>,
) -> Result<Json<ApiResponse<SignupVerified>>, ApiError> {
    let email = normalize_email(&req.email);
    match otp::verify_code(&state, OtpPurpose::Signup, &email, req.code.trim()).await? {
        VerifyResult::Ok => {}
        VerifyResult::Expired => {
            security::log(&state, event::OTP_EXPIRED, None, Some(ip), json!({ "email": email })).await;
            return Err(ApiError::BadRequest("This code has expired. Request a new one.".into()));
        }
        VerifyResult::Wrong { remaining } => {
            security::log(&state, event::OTP_FAILED, None, Some(ip), json!({ "email": email })).await;
            return Err(ApiError::BadRequest(format!(
                "Incorrect code. {remaining} attempt(s) remaining."
            )));
        }
        VerifyResult::TooManyAttempts => {
            security::log(&state, event::OTP_FAILED, None, Some(ip), json!({ "email": email, "exhausted": true })).await;
            return Err(ApiError::BadRequest(
                "Too many incorrect attempts. Request a new code.".into(),
            ));
        }
    }

    // Recover the stashed signup details.
    let mut r = state
        .redis
        .clone()
        .ok_or_else(|| ApiError::Internal("session store unavailable".into()))?;
    let stash: Option<String> = r.get(format!("pending_signup:{email}")).await.unwrap_or(None);
    let stash = stash.ok_or_else(|| {
        ApiError::BadRequest("Signup session expired. Please start again from your invite link.".into())
    })?;
    let parsed: serde_json::Value = serde_json::from_str(&stash).unwrap_or(json!({}));
    let code = parsed.get("code").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let display_name = parsed.get("display_name").and_then(|v| v.as_str()).unwrap_or("").to_string();

    // Re-check invite (could have been revoked/used since) and consume it.
    if !invite_is_usable(&state, &code).await? {
        return Err(ApiError::BadRequest(
            "This invite link is no longer valid. Ask the admin for a new one.".into(),
        ));
    }

    // Create the user (pending) and consume the invite atomically-ish.
    let mut tx = state.db.begin().await?;
    let user_id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (display_name, email, status) VALUES ($1, $2, 'pending') RETURNING id",
    )
    .bind(&display_name)
    .bind(&email)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            ApiError::Conflict("An account with this email already exists. Please log in.".into())
        }
        _ => ApiError::Db(e),
    })?;
    sqlx::query(
        "UPDATE invite_codes SET used_by = $1, used_at = NOW()
         WHERE LOWER(code) = LOWER($2) AND used_by IS NULL",
    )
    .bind(user_id)
    .bind(&code)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let _: Result<(), _> = r.del(format!("pending_signup:{email}")).await;
    security::log(&state, event::OTP_SUCCESS, Some(user_id), Some(ip), json!({ "purpose": "signup" })).await;
    security::log(&state, event::INVITE_USED, Some(user_id), Some(ip), json!({})).await;

    // Tell the admin someone wants in.
    notify::signup_request(&state, &display_name);

    Ok(Json(ApiResponse::ok(SignupVerified { status: "pending".into() })))
}

// ---- login -----------------------------------------------------------------

#[derive(Deserialize)]
pub struct LoginReq {
    pub email: String,
}

pub async fn login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<LoginReq>,
) -> Result<Json<ApiResponse<VerificationPending>>, ApiError> {
    let email = normalize_email(&req.email);
    if !valid_email(&email) {
        return Err(ApiError::BadRequest("a valid email is required".into()));
    }
    if otp::is_account_locked(&state, &email).await {
        return Err(ApiError::RateLimited(
            "This account is temporarily locked. Please contact the group admin.".into(),
        ));
    }
    otp::check_request_limits(&state, &email, ip).await?;

    // Only actually send a code to a real, non-revoked account — but always
    // return the same generic response so non-members can't be enumerated.
    let user: Option<(String,)> =
        sqlx::query_as("SELECT status FROM users WHERE LOWER(email) = $1")
            .bind(&email)
            .fetch_optional(&state.db)
            .await?;
    let mut resend_after = 0;
    if let Some((status,)) = user {
        if status == "active" || status == "pending" {
            let (code_value, ra) = otp::store_code(&state, OtpPurpose::Login, &email).await?;
            resend_after = ra;
            if ra == 0 {
                email::send_otp(&state, &email, &code_value).await.ok();
            }
            security::log(&state, event::OTP_ISSUED, None, Some(ip), json!({ "email": email, "purpose": "login" })).await;
        }
    }

    Ok(Json(ApiResponse::ok(VerificationPending {
        email,
        expires_in_minutes: otp::OTP_TTL_SECS / 60,
        delivery: if state.config.resend_api_key.is_some() { "email" } else { "server-log" },
        resend_after_secs: resend_after,
    })))
}

#[derive(Serialize)]
pub struct LoginResult {
    pub status: String,
    pub is_admin: bool,
}

pub async fn login_verify(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<VerifyReq>,
) -> Result<CookieResp<LoginResult>, ApiError> {
    let email = normalize_email(&req.email);
    if otp::is_account_locked(&state, &email).await {
        return Err(ApiError::RateLimited(
            "This account is temporarily locked. Please contact the group admin.".into(),
        ));
    }

    match otp::verify_code(&state, OtpPurpose::Login, &email, req.code.trim()).await? {
        VerifyResult::Ok => {}
        VerifyResult::Expired => {
            return Err(ApiError::BadRequest("This code has expired. Request a new one.".into()));
        }
        VerifyResult::Wrong { remaining } => {
            if otp::note_login_failure(&state, &email).await {
                security::log(&state, event::ACCOUNT_LOCKED, None, Some(ip), json!({ "email": email })).await;
                notify::signup_request(&state, &format!("⚠️ account locked: {email}"));
            }
            security::log(&state, event::LOGIN_FAILED, None, Some(ip), json!({ "email": email })).await;
            return Err(ApiError::BadRequest(format!(
                "Incorrect code. {remaining} attempt(s) remaining."
            )));
        }
        VerifyResult::TooManyAttempts => {
            otp::note_login_failure(&state, &email).await;
            security::log(&state, event::LOGIN_FAILED, None, Some(ip), json!({ "email": email, "exhausted": true })).await;
            return Err(ApiError::BadRequest(
                "Too many incorrect attempts. Request a new code.".into(),
            ));
        }
    }

    let user: Option<(Uuid, String, String, String)> =
        sqlx::query_as("SELECT id, status, role, email FROM users WHERE LOWER(email) = $1")
            .bind(&email)
            .fetch_optional(&state.db)
            .await?;
    let (id, status, role, user_email) =
        user.ok_or_else(|| ApiError::BadRequest("Unable to log in. Please contact the group admin.".into()))?;

    if status == "deactivated" || status == "rejected" {
        security::log(&state, event::LOGIN_FAILED, Some(id), Some(ip), json!({ "reason": status })).await;
        return Err(ApiError::Unauthorized);
    }

    let token = issue_token(id, &role, &state.config.jwt_secret)?;
    let cookie = auth_cookie(&token, state.config.cookie_secure);
    sqlx::query("UPDATE users SET last_active_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .ok();
    security::log(&state, event::OTP_SUCCESS, Some(id), Some(ip), json!({ "purpose": "login" })).await;
    security::log(&state, event::LOGIN_SUCCESS, Some(id), Some(ip), json!({})).await;

    let is_admin = role == "admin"
        || state.config.admin_email.as_deref() == Some(user_email.to_lowercase().as_str());

    Ok((
        AppendHeaders([(SET_COOKIE, cookie)]),
        Json(ApiResponse::ok(LoginResult { status, is_admin })),
    ))
}

// ---- session ---------------------------------------------------------------

pub async fn logout(
    State(state): State<AppState>,
    session: SessionUser,
) -> Result<CookieResp<()>, ApiError> {
    revoke_jti(&state, session.jti, session.exp).await;
    Ok((
        AppendHeaders([(SET_COOKIE, clear_auth_cookie(state.config.cookie_secure))]),
        Json(ApiResponse::message("Logged out.")),
    ))
}

pub async fn me(
    State(state): State<AppState>,
    session: SessionUser,
) -> Result<Json<ApiResponse<MeProfile>>, ApiError> {
    let mut profile: MeProfile = sqlx::query_as(
        "SELECT id, display_name, email, role, status, created_at, notif_prefs
         FROM users WHERE id = $1",
    )
    .bind(session.id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::Unauthorized)?;
    profile.is_admin = profile.role == "admin"
        || state.config.admin_email.as_deref() == Some(profile.email.to_lowercase().as_str());
    Ok(Json(ApiResponse::ok(profile)))
}

#[derive(Deserialize)]
pub struct UpdateMeReq {
    pub display_name: Option<String>,
    /// Map of notification category -> enabled.
    pub notif_prefs: Option<serde_json::Value>,
}

pub async fn update_me(
    State(state): State<AppState>,
    session: SessionUser,
    Json(req): Json<UpdateMeReq>,
) -> Result<Json<ApiResponse<MeProfile>>, ApiError> {
    if let Some(name) = &req.display_name {
        let name = name.trim();
        if !valid_display_name(name) {
            return Err(ApiError::BadRequest(
                "display name must be 2–30 letters, numbers or spaces".into(),
            ));
        }
        sqlx::query("UPDATE users SET display_name = $1 WHERE id = $2")
            .bind(name)
            .bind(session.id)
            .execute(&state.db)
            .await?;
    }
    if let Some(prefs) = &req.notif_prefs {
        if !prefs.is_object() {
            return Err(ApiError::BadRequest("notif_prefs must be an object".into()));
        }
        sqlx::query("UPDATE users SET notif_prefs = $1 WHERE id = $2")
            .bind(prefs)
            .bind(session.id)
            .execute(&state.db)
            .await?;
    }
    me(State(state), session).await
}
