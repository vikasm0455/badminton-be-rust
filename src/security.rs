//! Append-only security/audit log (PRD §10.3). Failures never break the
//! request that triggered them — logging is best-effort.

use std::net::IpAddr;

use uuid::Uuid;

use crate::state::AppState;

/// Canonical event_type strings (PRD §10.3).
pub mod event {
    pub const INVITE_CREATED: &str = "invite_created";
    pub const INVITE_USED: &str = "invite_used";
    pub const INVITE_REVOKED: &str = "invite_revoked";
    pub const SIGNUP_ATTEMPTED: &str = "signup_attempted";
    pub const OTP_ISSUED: &str = "otp_issued";
    pub const OTP_FAILED: &str = "otp_failed";
    pub const OTP_EXPIRED: &str = "otp_expired";
    pub const OTP_SUCCESS: &str = "otp_success";
    pub const LOGIN_SUCCESS: &str = "login_success";
    pub const LOGIN_FAILED: &str = "login_failed";
    pub const ACCOUNT_LOCKED: &str = "account_locked";
    pub const MEMBER_APPROVED: &str = "member_approved";
    pub const MEMBER_REJECTED: &str = "member_rejected";
    pub const MEMBER_DEACTIVATED: &str = "member_deactivated";
    pub const MEMBER_REACTIVATED: &str = "member_reactivated";
    pub const CREDENTIAL_POSTED: &str = "credential_posted";
    pub const CREDENTIAL_DELETED: &str = "credential_deleted";
    pub const INVALID_INVITE_ATTEMPT: &str = "invalid_invite_attempt";
    pub const ADMIN_ACTION: &str = "admin_action";
}

pub async fn log(
    state: &AppState,
    event_type: &str,
    user_id: Option<Uuid>,
    ip: Option<IpAddr>,
    metadata: serde_json::Value,
) {
    let ip_str = ip.map(|i| i.to_string());
    let res = sqlx::query(
        "INSERT INTO security_events (event_type, user_id, ip_address, metadata)
         VALUES ($1, $2, $3::text::inet, $4)",
    )
    .bind(event_type)
    .bind(user_id)
    .bind(ip_str)
    .bind(metadata)
    .execute(&state.db)
    .await;
    if let Err(e) = res {
        tracing::warn!(error = %e, event_type, "failed to write security event");
    }
}
