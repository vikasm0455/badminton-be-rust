use axum::async_trait;
use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::state::AppState;

const TOKEN_LIFETIME_DAYS: i64 = 30;
pub const TOKEN_LIFETIME_SECS: i64 = TOKEN_LIFETIME_DAYS * 24 * 60 * 60;
pub const AUTH_COOKIE: &str = "token";

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub role: String,
    pub iat: i64,
    pub exp: i64,
    /// Per-token id, so a single device can be logged out without nuking others.
    pub jti: Uuid,
}

pub fn issue_token(user_id: Uuid, role: &str, secret: &str) -> Result<String, ApiError> {
    let now = Utc::now();
    let claims = Claims {
        sub: user_id,
        role: role.to_string(),
        iat: now.timestamp(),
        exp: (now + Duration::days(TOKEN_LIFETIME_DAYS)).timestamp(),
        jti: Uuid::new_v4(),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| ApiError::Internal(format!("token signing failed: {e}")))
}

pub fn decode_token(token: &str, secret: &str) -> Option<Claims> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .ok()
}

/// HttpOnly Secure SameSite=Strict cookie (PRD §4.4). 30-day TTL.
pub fn auth_cookie(token: &str, secure: bool) -> String {
    format!(
        "{AUTH_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={TOKEN_LIFETIME_SECS}{}",
        if secure { "; Secure" } else { "" }
    )
}

pub fn clear_auth_cookie(secure: bool) -> String {
    format!(
        "{AUTH_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{}",
        if secure { "; Secure" } else { "" }
    )
}

fn token_from_parts(parts: &Parts) -> Option<String> {
    if let Some(token) = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        return Some(token.to_string());
    }
    parts
        .headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())?
        .split(';')
        .map(str::trim)
        .find_map(|c| c.strip_prefix("token="))
        .map(str::to_string)
}

/// Revoke one token (logout, single device): blocklist its jti until it expires.
pub async fn revoke_jti(state: &AppState, jti: Uuid, exp: i64) {
    if let Some(mut redis) = state.redis.clone() {
        let ttl = (exp - Utc::now().timestamp()).max(1);
        let _: Result<(), _> = redis
            .set_ex(format!("blocklist:jti:{jti}"), 1, ttl as u64)
            .await;
    }
}

/// Revoke all of a user's tokens (deactivation): tokens issued before now fail.
pub async fn revoke_all_for_user(state: &AppState, user_id: Uuid) {
    if let Some(mut redis) = state.redis.clone() {
        let _: Result<(), _> = redis
            .set_ex(
                format!("revoke_before:{user_id}"),
                Utc::now().timestamp(),
                TOKEN_LIFETIME_SECS as u64,
            )
            .await;
    }
}

async fn is_revoked(state: &AppState, claims: &Claims) -> bool {
    let Some(mut redis) = state.redis.clone() else {
        return false; // no Redis → fail open (blocklist unavailable)
    };
    // Single-device logout.
    if let Ok(true) = redis.exists::<_, bool>(format!("blocklist:jti:{}", claims.jti)).await {
        return true;
    }
    // Mass revocation (deactivation): reject tokens issued before the cutoff.
    if let Ok(Some(cutoff)) = redis
        .get::<_, Option<i64>>(format!("revoke_before:{}", claims.sub))
        .await
    {
        if claims.iat < cutoff {
            return true;
        }
    }
    false
}

/// Any valid, non-revoked session — regardless of account status. Used by
/// `/api/auth/me` and `/pending` so the frontend can route by status.
#[derive(Debug, Clone)]
pub struct SessionUser {
    pub id: Uuid,
    pub role: String,
    pub status: String,
    pub jti: Uuid,
    pub exp: i64,
}

#[async_trait]
impl FromRequestParts<AppState> for SessionUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = token_from_parts(parts).ok_or(ApiError::Unauthorized)?;
        let claims = decode_token(&token, &state.config.jwt_secret).ok_or(ApiError::Unauthorized)?;
        if is_revoked(state, &claims).await {
            return Err(ApiError::Unauthorized);
        }
        let status: Option<(String,)> = sqlx::query_as("SELECT status FROM users WHERE id = $1")
            .bind(claims.sub)
            .fetch_optional(&state.db)
            .await?;
        let status = status.ok_or(ApiError::Unauthorized)?.0;
        if status == "deactivated" || status == "rejected" {
            return Err(ApiError::Unauthorized);
        }
        Ok(SessionUser {
            id: claims.sub,
            role: claims.role,
            status,
            jti: claims.jti,
            exp: claims.exp,
        })
    }
}

/// An approved, active member. Pending users are rejected with 403 so the
/// frontend redirects them to /pending.
#[derive(Debug, Clone, Copy)]
pub struct AuthUser {
    pub id: Uuid,
}

#[async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let session = SessionUser::from_request_parts(parts, state).await?;
        if session.status != "active" {
            return Err(ApiError::Forbidden);
        }
        // Sliding-window last-active touch (best effort).
        let _ = sqlx::query("UPDATE users SET last_active_at = NOW() WHERE id = $1")
            .bind(session.id)
            .execute(&state.db)
            .await;
        Ok(AuthUser { id: session.id })
    }
}

/// Admin-only. Returns 403 (PRD §19.3) for authenticated non-admins.
#[derive(Debug, Clone, Copy)]
pub struct AdminUser {
    pub id: Uuid,
}

#[async_trait]
impl FromRequestParts<AppState> for AdminUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let session = SessionUser::from_request_parts(parts, state).await?;
        if session.status != "active" {
            return Err(ApiError::Forbidden);
        }
        let row: Option<(String, String)> =
            sqlx::query_as("SELECT email, role FROM users WHERE id = $1")
                .bind(session.id)
                .fetch_optional(&state.db)
                .await?;
        let (email, role) = row.ok_or(ApiError::Forbidden)?;
        let email_match = state
            .config
            .admin_email
            .as_deref()
            .is_some_and(|a| a == email.to_lowercase());
        if role == "admin" || email_match {
            Ok(AdminUser { id: session.id })
        } else {
            Err(ApiError::Forbidden)
        }
    }
}
