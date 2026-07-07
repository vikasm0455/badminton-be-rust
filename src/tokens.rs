//! Rotating refresh tokens for the native mobile apps (Phase 0, W0.2).
//!
//! Native clients get a short-lived access JWT plus a long-lived, SINGLE-USE
//! refresh token. Each refresh rotates the token within a `family`; presenting
//! an already-used token is treated as theft/replay and revokes the entire
//! family. Only SHA-256 hashes are stored.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use rand::RngCore;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::ApiError;
use crate::state::AppState;

pub const REFRESH_LIFETIME_DAYS: i64 = 90;
/// Native access JWTs are short-lived; the refresh token does the long haul.
pub const NATIVE_ACCESS_DAYS: i64 = 1;

/// A just-used refresh token may be presented again briefly: mobile networks
/// drop responses, and the client's only sane move is to retry the same token.
/// Within the grace window we mint another successor instead of treating the
/// retry as theft. Overridable for tests via REFRESH_REUSE_GRACE_SECS.
fn reuse_grace_secs() -> i64 {
    std::env::var("REFRESH_REUSE_GRACE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60)
}

fn hash(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    hex::encode(h.finalize())
}

// Tiny local hex encoder to avoid another dependency.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Mint a fresh refresh token for `user_id`. `family` is None on login (new
/// chain) and Some on rotation (same chain).
pub async fn issue(state: &AppState, user_id: Uuid, family: Option<Uuid>) -> Result<String, ApiError> {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let secret = URL_SAFE_NO_PAD.encode(bytes);
    sqlx::query(
        "INSERT INTO refresh_tokens (user_id, token_hash, family, expires_at)
         VALUES ($1, $2, $3, NOW() + make_interval(days => $4))",
    )
    .bind(user_id)
    .bind(hash(&secret))
    .bind(family.unwrap_or_else(Uuid::new_v4))
    .bind(REFRESH_LIFETIME_DAYS as i32)
    .execute(&state.db)
    .await?;
    Ok(secret)
}

#[derive(sqlx::FromRow)]
struct RefreshRow {
    id: Uuid,
    user_id: Uuid,
    family: Uuid,
    expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    user_status: String,
}

/// Exchange a refresh token: valid+unused → (user_id, new refresh token) with
/// the old one consumed. A token re-presented within the short grace window
/// (lost response → client retry) mints another successor; re-presented later
/// it's treated as theft and the whole family is revoked. Deactivated users
/// are rejected BEFORE the token is consumed.
pub async fn rotate(state: &AppState, presented: &str) -> Result<Option<(Uuid, String)>, ApiError> {
    let row: Option<RefreshRow> = sqlx::query_as(
        "SELECT rt.id, rt.user_id, rt.family, rt.expires_at, rt.used_at, rt.revoked_at,
                u.status AS user_status
         FROM refresh_tokens rt JOIN users u ON u.id = rt.user_id
         WHERE rt.token_hash = $1",
    )
    .bind(hash(presented))
    .fetch_optional(&state.db)
    .await?;
    let Some(row) = row else { return Ok(None) };

    if row.revoked_at.is_some() || row.expires_at <= Utc::now() || row.user_status != "active" {
        return Ok(None);
    }
    if let Some(used) = row.used_at {
        if (Utc::now() - used).num_seconds() <= reuse_grace_secs() {
            // Network-retry grace: same token again right after rotation.
            let next = issue(state, row.user_id, Some(row.family)).await?;
            return Ok(Some((row.user_id, next)));
        }
        revoke_family(state, row.family).await?;
        tracing::warn!(user = %row.user_id, "refresh token REUSE detected — family revoked");
        return Ok(None);
    }

    // Single-use claim; a concurrent rotation of the same token loses this race
    // and takes the grace path above on its retry (used_at is seconds old).
    let claimed = sqlx::query("UPDATE refresh_tokens SET used_at = NOW() WHERE id = $1 AND used_at IS NULL")
        .bind(row.id)
        .execute(&state.db)
        .await?;
    if claimed.rows_affected() == 0 {
        let next = issue(state, row.user_id, Some(row.family)).await?;
        return Ok(Some((row.user_id, next)));
    }

    let next = issue(state, row.user_id, Some(row.family)).await?;
    Ok(Some((row.user_id, next)))
}

async fn revoke_family(state: &AppState, family: Uuid) -> Result<(), ApiError> {
    sqlx::query("UPDATE refresh_tokens SET revoked_at = NOW() WHERE family = $1 AND revoked_at IS NULL")
        .bind(family)
        .execute(&state.db)
        .await?;
    Ok(())
}

/// Revoke one presented token (native logout).
pub async fn revoke(state: &AppState, presented: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_hash = $1 AND revoked_at IS NULL")
        .bind(hash(presented))
        .execute(&state.db)
        .await?;
    Ok(())
}

/// Revoke every refresh token a user has (deactivation / account deletion).
pub async fn revoke_all_for_user(state: &AppState, user_id: Uuid) -> Result<(), ApiError> {
    sqlx::query("UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL")
        .bind(user_id)
        .execute(&state.db)
        .await?;
    Ok(())
}
