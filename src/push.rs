//! Web Push (VAPID) — key management + fan-out (PRD §8).
//!
//! The VAPID keypair is generated on first boot and persisted to `app_config`.
//! Fan-out runs in a detached task so it never blocks the API request that
//! triggered it; delivery failures are logged, and gone endpoints (404/410)
//! are marked inactive.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;
use web_push::{
    ContentEncoding, HyperWebPushClient, SubscriptionInfo, VapidSignatureBuilder, WebPushClient,
    WebPushError, WebPushMessageBuilder,
};

use crate::state::AppState;

pub struct Vapid {
    /// Browser `applicationServerKey` — uncompressed P-256 point, base64url no-pad.
    pub public_key_b64: String,
    /// PKCS#8 PEM private key, fed to the signature builder.
    private_pem: String,
    subject: String,
}

impl Vapid {
    /// Load the keypair from app_config, generating and persisting one on first boot.
    pub async fn load_or_create(db: &PgPool, subject: &str) -> Self {
        if let (Some(pubk), Some(pem)) = (
            read_config(db, "vapid_public_key").await,
            read_config(db, "vapid_private_key").await,
        ) {
            return Vapid {
                public_key_b64: pubk,
                private_pem: pem,
                subject: subject.to_string(),
            };
        }

        // Generate a fresh P-256 keypair.
        use p256::elliptic_curve::rand_core::OsRng;
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use p256::pkcs8::{EncodePrivateKey, LineEnding};
        let secret = p256::SecretKey::random(&mut OsRng);
        let pem = secret
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode VAPID private key")
            .to_string();
        let point = secret.public_key().to_encoded_point(false);
        let public_key_b64 = URL_SAFE_NO_PAD.encode(point.as_bytes());

        write_config(db, "vapid_public_key", &public_key_b64).await;
        write_config(db, "vapid_private_key", &pem).await;
        tracing::info!("generated new VAPID keypair");

        Vapid {
            public_key_b64,
            private_pem: pem,
            subject: subject.to_string(),
        }
    }
}

async fn read_config(db: &PgPool, key: &str) -> Option<String> {
    sqlx::query_as::<_, (String,)>("SELECT value FROM app_config WHERE key = $1")
        .bind(key)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .map(|r| r.0)
        .filter(|v| !v.is_empty())
}

async fn write_config(db: &PgPool, key: &str, value: &str) {
    let _ = sqlx::query(
        "INSERT INTO app_config (key, value, updated_at) VALUES ($1, $2, NOW())
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
    )
    .bind(key)
    .bind(value)
    .execute(db)
    .await;
}

/// What the Service Worker receives (`event.data.json()`).
#[derive(Debug, Clone, Serialize)]
pub struct PushPayload {
    pub title: String,
    pub body: String,
    /// Deep link the SW opens on click, e.g. "/courts".
    pub url: String,
    /// Collapse tag — newer notifications with the same tag replace older ones.
    pub tag: String,
}

impl PushPayload {
    pub fn new(
        title: impl Into<String>,
        body: impl Into<String>,
        url: impl Into<String>,
        tag: impl Into<String>,
    ) -> Self {
        Self { title: title.into(), body: body.into(), url: url.into(), tag: tag.into() }
    }
}

#[derive(sqlx::FromRow)]
struct SubRow {
    id: Uuid,
    endpoint: String,
    p256dh: String,
    auth: String,
}

/// Send to all active members; `exclude` skips one user (e.g. the actor).
/// `category` is checked against each user's notif_prefs (opt-out model).
pub fn notify_all(state: &AppState, payload: PushPayload, exclude: Option<Uuid>, category: &str) {
    let state = state.clone();
    let category = category.to_string();
    tokio::spawn(async move {
        let subs: Vec<SubRow> = sqlx::query_as(
            "SELECT ps.id, ps.endpoint, ps.p256dh, ps.auth
             FROM push_subscriptions ps
             JOIN users u ON u.id = ps.user_id
             WHERE ps.active = true AND u.status = 'active'
               AND ($1::uuid IS NULL OR ps.user_id <> $1)
               AND COALESCE((u.notif_prefs ->> $2)::boolean, true) = true",
        )
        .bind(exclude)
        .bind(&category)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();
        deliver(&state, subs, &payload).await;
    });
}

/// Send to one specific user's devices.
pub fn notify_user(state: &AppState, user_id: Uuid, payload: PushPayload, category: &str) {
    let state = state.clone();
    let category = category.to_string();
    tokio::spawn(async move {
        let subs: Vec<SubRow> = sqlx::query_as(
            "SELECT ps.id, ps.endpoint, ps.p256dh, ps.auth
             FROM push_subscriptions ps
             JOIN users u ON u.id = ps.user_id
             WHERE ps.active = true AND ps.user_id = $1
               AND COALESCE((u.notif_prefs ->> $2)::boolean, true) = true",
        )
        .bind(user_id)
        .bind(&category)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();
        deliver(&state, subs, &payload).await;
    });
}

/// Send to the admin(s): role = 'admin' or the configured ADMIN_EMAIL.
pub fn notify_admins(state: &AppState, payload: PushPayload) {
    let state = state.clone();
    let admin_email = state.config.admin_email.clone();
    tokio::spawn(async move {
        let subs: Vec<SubRow> = sqlx::query_as(
            "SELECT ps.id, ps.endpoint, ps.p256dh, ps.auth
             FROM push_subscriptions ps
             JOIN users u ON u.id = ps.user_id
             WHERE ps.active = true
               AND (u.role = 'admin' OR LOWER(u.email) = $1)",
        )
        .bind(admin_email)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();
        deliver(&state, subs, &payload).await;
    });
}

async fn deliver(state: &AppState, subs: Vec<SubRow>, payload: &PushPayload) {
    if subs.is_empty() {
        return;
    }
    let client = HyperWebPushClient::new();
    let body = serde_json::to_vec(payload).unwrap_or_default();

    for sub in subs {
        match build_message(state, &sub, &body) {
            Ok(message) => match client.send(message).await {
                Ok(()) => {
                    crate::metrics::record_push("ok");
                    let _ = sqlx::query(
                        "UPDATE push_subscriptions SET last_success_at = NOW() WHERE id = $1",
                    )
                    .bind(sub.id)
                    .execute(&state.db)
                    .await;
                }
                Err(WebPushError::EndpointNotFound | WebPushError::EndpointNotValid) => {
                    crate::metrics::record_push("gone");
                    tracing::info!(sub = %sub.id, "push endpoint gone — deactivating");
                    let _ = sqlx::query(
                        "UPDATE push_subscriptions SET active = false WHERE id = $1",
                    )
                    .bind(sub.id)
                    .execute(&state.db)
                    .await;
                }
                Err(e) => {
                    crate::metrics::record_push("failed");
                    tracing::warn!(error = %e, sub = %sub.id, "push delivery failed");
                }
            },
            Err(e) => {
                crate::metrics::record_push("failed");
                tracing::warn!(error = %e, "failed to build push message");
            }
        }
    }
}

fn build_message(
    state: &AppState,
    sub: &SubRow,
    body: &[u8],
) -> Result<web_push::WebPushMessage, WebPushError> {
    let info = SubscriptionInfo::new(&sub.endpoint, &sub.p256dh, &sub.auth);
    let mut sig = VapidSignatureBuilder::from_pem(state.vapid.private_pem.as_bytes(), &info)?;
    sig.add_claim("sub", state.vapid.subject.clone());
    let signature = sig.build()?;

    let mut builder = WebPushMessageBuilder::new(&info);
    builder.set_payload(ContentEncoding::Aes128Gcm, body);
    builder.set_vapid_signature(signature);
    builder.build()
}
