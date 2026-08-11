use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use redis::aio::ConnectionManager;
use sqlx::PgPool;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::config::Config;
use crate::native_push::NativePush;
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
    /// APNs/FCM senders for the native apps (env-gated; no-op when unconfigured).
    pub native: Arc<NativePush>,
    /// Broadcast bus for SSE live updates.
    pub events: broadcast::Sender<LiveEvent>,
    /// Global per-IP API rate limiter (PRD §19.3: 100 req/min/IP).
    pub rate_api: Arc<RateLimiter>,
    /// Per-club nudge channels for the Courts kiosk board SSE
    /// (/api/clubs/{slug}/board/stream). Subscribers rebuild the board on
    /// every nudge; the channel carries no payload.
    pub club_events: ClubEvents,
}

/// Lazily-created broadcast channel per club. A plain Mutex<HashMap> is enough:
/// lock hold time is a map lookup, and the fan-out itself happens outside it.
pub type ClubEvents = Arc<Mutex<HashMap<Uuid, broadcast::Sender<()>>>>;

pub fn new_club_events() -> ClubEvents {
    Arc::new(Mutex::new(HashMap::new()))
}

impl AppState {
    /// Best-effort broadcast — ignores the "no subscribers" error.
    pub fn broadcast(&self, event: LiveEvent) {
        let _ = self.events.send(event);
    }

    /// Get (or create) the nudge channel for one club's kiosk board.
    /// Opportunistically evicts channels no kiosk is listening to any more
    /// (skipping the club being fetched), so the map tracks live clubs rather
    /// than every club ever streamed.
    pub fn club_channel(&self, club_id: Uuid) -> broadcast::Sender<()> {
        let mut map = self.club_events.lock().expect("club_events lock");
        map.retain(|id, tx| *id == club_id || tx.receiver_count() > 0);
        map.entry(club_id)
            .or_insert_with(|| broadcast::channel(64).0)
            .clone()
    }

    /// Nudge every kiosk streaming this club's board (best effort).
    pub fn notify_club(&self, club_id: Uuid) {
        let sender = {
            let map = self.club_events.lock().expect("club_events lock");
            map.get(&club_id).cloned()
        };
        if let Some(tx) = sender {
            let _ = tx.send(());
        }
    }
}
