use std::sync::Arc;

use redis::aio::ConnectionManager;
use sqlx::PgPool;
use tokio::sync::broadcast;

use crate::config::Config;
use crate::net::RateLimiter;
use crate::push::Vapid;

/// Real-time events fanned out to connected SSE clients (PRD §14.4
/// /api/reservations/stream). Kept deliberately small — the client refetches
/// on any nudge rather than receiving full payloads over the stream.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LiveEvent {
    /// Something about today's reservations changed; clients should refetch.
    ReservationsChanged,
    /// A poll vote changed; clients viewing the poll should refetch.
    PollChanged { poll_id: uuid::Uuid },
    /// A new credential was posted.
    CredentialsChanged,
    /// A kcal log was added/edited.
    KcalChanged,
    /// Heartbeat so proxies don't close idle streams.
    Ping,
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub http: reqwest::Client,
    /// None when Redis is unreachable — rate limiting then fails open.
    pub redis: Option<ConnectionManager>,
    /// Lazy pool: created without connecting, so the app boots with no DB up.
    pub db: PgPool,
    /// VAPID keypair for Web Push (generated on first boot, stored in app_config).
    pub vapid: Arc<Vapid>,
    /// Broadcast bus for SSE live updates.
    pub events: broadcast::Sender<LiveEvent>,
    /// Global per-IP API rate limiter (PRD §19.3: 100 req/min/IP).
    pub rate_api: Arc<RateLimiter>,
}

impl AppState {
    /// Best-effort broadcast — ignores the "no subscribers" error.
    pub fn broadcast(&self, event: LiveEvent) {
        let _ = self.events.send(event);
    }
}
