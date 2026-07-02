//! OTP generation/verification + Redis-backed brute-force protection (PRD §4.3).
//!
//! Everything here depends on Redis. When Redis is unreachable the OTP cannot
//! be stored, so the flow returns an error rather than silently failing open —
//! OTP *is* the auth factor, it can't be bypassed.

use std::net::IpAddr;

use rand::Rng;
use redis::AsyncCommands;
use uuid::Uuid;

use crate::error::ApiError;
use crate::state::AppState;

pub const OTP_TTL_SECS: i64 = 5 * 60;
pub const RESEND_COOLDOWN_SECS: i64 = 60;
pub const MAX_OTP_ATTEMPTS: u32 = 3;

const MAX_OTP_REQ_PER_EMAIL: u32 = 5; // per 60 min
const MAX_OTP_REQ_PER_IP: u32 = 15; // per 60 min
const OTP_REQ_WINDOW_SECS: i64 = 60 * 60;
const MAX_INVITE_TRY_PER_IP: u32 = 10; // per hour
const INVITE_TRY_WINDOW_SECS: i64 = 60 * 60;
const LOCKOUT_THRESHOLD: u32 = 10; // cumulative failed login OTPs / 24h
const LOCKOUT_WINDOW_SECS: i64 = 24 * 60 * 60;

#[derive(Clone, Copy, PartialEq)]
pub enum OtpPurpose {
    Signup,
    Login,
}

impl OtpPurpose {
    fn tag(&self) -> &'static str {
        match self {
            OtpPurpose::Signup => "signup",
            OtpPurpose::Login => "login",
        }
    }
}

pub enum VerifyResult {
    Ok,
    Expired,
    Wrong { remaining: u32 },
    TooManyAttempts,
}

fn redis(state: &AppState) -> Result<redis::aio::ConnectionManager, ApiError> {
    state
        .redis
        .clone()
        .ok_or_else(|| ApiError::Internal("verification service unavailable (no Redis)".into()))
}

pub fn generate_code() -> String {
    let n: u32 = rand::thread_rng().gen_range(0..1_000_000);
    format!("{n:06}")
}

/// Sliding-window limiter using a Redis sorted set keyed by timestamp. Returns
/// (allowed, retry_after_secs). When Redis is down it fails open.
async fn sliding_window(
    state: &AppState,
    key: &str,
    max: u32,
    window_secs: i64,
) -> (bool, i64) {
    let Some(mut r) = state.redis.clone() else {
        return (true, 0);
    };
    let now = crate::time::now().timestamp_millis();
    let cutoff = now - window_secs * 1000;
    let member = format!("{now}-{}", Uuid::new_v4());

    let _: Result<(), _> = r.zrembyscore(key, 0, cutoff).await;
    let count: u32 = r.zcard(key).await.unwrap_or(0);
    if count >= max {
        // Oldest entry's score tells us when a slot frees up.
        let oldest: Vec<(String, i64)> = r.zrange_withscores(key, 0, 0).await.unwrap_or_default();
        let retry = oldest
            .first()
            .map(|(_, score)| ((score + window_secs * 1000 - now) / 1000).max(1))
            .unwrap_or(window_secs);
        return (false, retry);
    }
    let _: Result<(), _> = r.zadd(key, member, now).await;
    let _: Result<(), _> = r.expire(key, window_secs).await;
    (true, 0)
}

/// Enforce per-email and per-IP OTP request limits before issuing a code.
pub async fn check_request_limits(
    state: &AppState,
    email: &str,
    ip: IpAddr,
) -> Result<(), ApiError> {
    let (ok, retry) = sliding_window(
        state,
        &format!("otp_req:{email}"),
        MAX_OTP_REQ_PER_EMAIL,
        OTP_REQ_WINDOW_SECS,
    )
    .await;
    if !ok {
        return Err(ApiError::RateLimited(format!(
            "Too many requests. Try again in {} minutes.",
            (retry + 59) / 60
        )));
    }
    let (ok, retry) = sliding_window(
        state,
        &format!("otp_req:ip:{ip}"),
        MAX_OTP_REQ_PER_IP,
        OTP_REQ_WINDOW_SECS,
    )
    .await;
    if !ok {
        return Err(ApiError::RateLimited(format!(
            "Too many requests. Try again in {} minutes.",
            (retry + 59) / 60
        )));
    }
    Ok(())
}

/// Store a freshly generated code. Returns the code to deliver. If a still-valid
/// code was issued < cooldown ago, returns the remaining cooldown so the caller
/// can avoid re-sending (resend button gating).
pub async fn store_code(
    state: &AppState,
    purpose: OtpPurpose,
    email: &str,
) -> Result<(String, i64), ApiError> {
    let mut r = redis(state)?;
    let key = format!("otp:{}:{email}", purpose.tag());
    let sent_key = format!("otp:{}:{email}:sent_at", purpose.tag());

    // Cooldown gate.
    if let Ok(Some(sent_at)) = r.get::<_, Option<i64>>(&sent_key).await {
        let elapsed = crate::time::now().timestamp() - sent_at;
        if elapsed < RESEND_COOLDOWN_SECS {
            // Reuse the existing code if still present.
            if let Ok(Some(existing)) = r.get::<_, Option<String>>(&key).await {
                return Ok((existing, RESEND_COOLDOWN_SECS - elapsed));
            }
        }
    }

    let code = generate_code();
    let _: () = r
        .set_ex(&key, &code, OTP_TTL_SECS as u64)
        .await
        .map_err(|e| ApiError::Internal(format!("redis: {e}")))?;
    let _: () = r
        .set_ex(&sent_key, crate::time::now().timestamp(), OTP_TTL_SECS as u64)
        .await
        .map_err(|e| ApiError::Internal(format!("redis: {e}")))?;
    let _: () = r
        .set_ex(
            format!("otp:{}:{email}:attempts", purpose.tag()),
            0,
            OTP_TTL_SECS as u64,
        )
        .await
        .map_err(|e| ApiError::Internal(format!("redis: {e}")))?;

    Ok((code, 0))
}

pub async fn verify_code(
    state: &AppState,
    purpose: OtpPurpose,
    email: &str,
    submitted: &str,
) -> Result<VerifyResult, ApiError> {
    let mut r = redis(state)?;
    let key = format!("otp:{}:{email}", purpose.tag());
    let attempts_key = format!("otp:{}:{email}:attempts", purpose.tag());

    let stored: Option<String> = r.get(&key).await.unwrap_or(None);
    let Some(stored) = stored else {
        return Ok(VerifyResult::Expired);
    };

    if stored == submitted {
        let _: Result<(), _> = r.del(&key).await;
        let _: Result<(), _> = r.del(&attempts_key).await;
        return Ok(VerifyResult::Ok);
    }

    // Wrong code: bump attempt counter.
    let attempts: u32 = r.incr(&attempts_key, 1).await.unwrap_or(MAX_OTP_ATTEMPTS);
    let _: Result<(), _> = r.expire(&attempts_key, OTP_TTL_SECS).await;
    if attempts >= MAX_OTP_ATTEMPTS {
        let _: Result<(), _> = r.del(&key).await;
        return Ok(VerifyResult::TooManyAttempts);
    }
    Ok(VerifyResult::Wrong {
        remaining: MAX_OTP_ATTEMPTS - attempts,
    })
}

/// Record a failed login OTP toward the 24h lockout threshold. Returns true if
/// this failure crossed the threshold (account just got flagged).
pub async fn note_login_failure(state: &AppState, email: &str) -> bool {
    let Some(mut r) = state.redis.clone() else {
        return false;
    };
    let key = format!("failcount:{email}");
    let count: u32 = r.incr(&key, 1).await.unwrap_or(0);
    let _: Result<(), _> = r.expire(&key, LOCKOUT_WINDOW_SECS).await;
    if count == LOCKOUT_THRESHOLD {
        let _: Result<(), _> = r
            .set_ex(format!("lockflag:{email}"), 1, LOCKOUT_WINDOW_SECS as u64)
            .await;
        return true;
    }
    false
}

pub async fn is_account_locked(state: &AppState, email: &str) -> bool {
    let Some(mut r) = state.redis.clone() else {
        return false;
    };
    r.exists(format!("lockflag:{email}")).await.unwrap_or(false)
}

/// Admin clears a lockout flag (also resets the failure counter).
pub async fn clear_account_lock(state: &AppState, email: &str) {
    if let Some(mut r) = state.redis.clone() {
        let _: Result<(), _> = r.del(format!("lockflag:{email}")).await;
        let _: Result<(), _> = r.del(format!("failcount:{email}")).await;
    }
}

/// Invite-code attempt limiter (PRD §4.3: 10 per IP per hour).
// LEGACY-SINGLE-TENANT: no callers since invite codes were replaced by group email
// invites — delete with the invite-code system.
pub async fn check_invite_attempt(state: &AppState, ip: IpAddr) -> Result<(), ApiError> {
    let (ok, _retry) = sliding_window(
        state,
        &format!("invite_try:ip:{ip}"),
        MAX_INVITE_TRY_PER_IP,
        INVITE_TRY_WINDOW_SECS,
    )
    .await;
    if ok {
        Ok(())
    } else {
        Err(ApiError::RateLimited(
            "Too many attempts. Please try again later.".into(),
        ))
    }
}
