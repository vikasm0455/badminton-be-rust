use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

/// Uniform response envelope: `{ success, data, message }` (matches house style).
#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub data: Option<T>,
    pub message: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self { success: true, data: Some(data), message: None }
    }
    pub fn ok_msg(data: T, message: impl Into<String>) -> Self {
        Self { success: true, data: Some(data), message: Some(message.into()) }
    }
}

impl ApiResponse<()> {
    pub fn message(message: impl Into<String>) -> Self {
        Self { success: true, data: None, message: Some(message.into()) }
    }
}

/// A user as exposed to other members (no email beyond admin views).
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct PublicUser {
    pub id: Uuid,
    pub display_name: String,
}

/// The signed-in user's own profile.
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct MeProfile {
    pub id: Uuid,
    pub display_name: String,
    pub email: String,
    pub role: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    #[sqlx(default)]
    pub is_admin: bool,
    pub notif_prefs: serde_json::Value,
}
