//! APNs (iOS) + FCM (Android) push senders — Phase 0 (W0.4).
//!
//! Both are env-gated and degrade to a graceful no-op when unconfigured (the
//! Resend/Anthropic pattern), so this ships before any store account exists.
//!
//!   APNS_KEY_P8       path to the .p8 token-auth key from the Apple dev portal
//!   APNS_KEY_ID       key id for that .p8
//!   APNS_TEAM_ID      Apple team id
//!   APNS_BUNDLE_ID    app bundle id (apns-topic)
//!   APNS_SANDBOX      "true" → sandbox gateway (Xcode/TestFlight dev builds)
//!   FCM_SERVICE_ACCOUNT  path to a Firebase service-account JSON
//!
//! Auth tokens are minted locally (ES256 for APNs, RS256 OAuth grant for FCM)
//! and cached briefly; delivery calls go through downstream::send so the
//! existing dependency metrics cover both gateways.

use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;
use serde_json::json;
use tokio::sync::Mutex;

use crate::push::PushPayload;
use crate::state::AppState;

const APNS_JWT_TTL_SECS: i64 = 45 * 60; // Apple allows 20–60 min
const FCM_TOKEN_SLACK_SECS: i64 = 5 * 60;

/// APNs caps apns-collapse-id at 64 BYTES; truncate on a char boundary.
fn collapse_id(tag: &str) -> String {
    let mut out = String::new();
    for c in tag.chars() {
        if out.len() + c.len_utf8() > 64 {
            break;
        }
        out.push(c);
    }
    out
}

pub struct ApnsConfig {
    key_pem: Vec<u8>,
    key_id: String,
    team_id: String,
    topic: String,
    endpoint: &'static str,
}

pub struct FcmConfig {
    client_email: String,
    private_key_pem: String,
    project_id: String,
}

#[derive(Default)]
pub struct NativePush {
    pub apns: Option<ApnsConfig>,
    pub fcm: Option<FcmConfig>,
    apns_jwt: Mutex<Option<(String, i64)>>,
    fcm_token: Mutex<Option<(String, i64)>>,
}

impl NativePush {
    /// Load from env at boot. Missing/broken config → that channel is off.
    pub fn from_env() -> Self {
        let apns = (|| {
            let path = std::env::var("APNS_KEY_P8").ok().filter(|v| !v.is_empty())?;
            let key_id = std::env::var("APNS_KEY_ID").ok().filter(|v| !v.is_empty())?;
            let team_id = std::env::var("APNS_TEAM_ID").ok().filter(|v| !v.is_empty())?;
            let topic = std::env::var("APNS_BUNDLE_ID").ok().filter(|v| !v.is_empty())?;
            let key_pem = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(error = %e, path, "APNS_KEY_P8 unreadable — APNs disabled");
                    return None;
                }
            };
            let sandbox = std::env::var("APNS_SANDBOX")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            Some(ApnsConfig {
                key_pem,
                key_id,
                team_id,
                topic,
                endpoint: if sandbox { "https://api.sandbox.push.apple.com" } else { "https://api.push.apple.com" },
            })
        })();

        let fcm = (|| {
            let path = std::env::var("FCM_SERVICE_ACCOUNT").ok().filter(|v| !v.is_empty())?;
            let raw = match std::fs::read_to_string(&path) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, path, "FCM_SERVICE_ACCOUNT unreadable — FCM disabled");
                    return None;
                }
            };
            let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
            Some(FcmConfig {
                client_email: v.get("client_email")?.as_str()?.to_string(),
                private_key_pem: v.get("private_key")?.as_str()?.to_string(),
                project_id: v.get("project_id")?.as_str()?.to_string(),
            })
        })();

        if apns.is_some() {
            tracing::info!("APNs push enabled");
        }
        if fcm.is_some() {
            tracing::info!("FCM push enabled");
        }
        NativePush { apns, fcm, ..Default::default() }
    }

    /// Cached provider JWT for APNs (ES256, regenerated ~45 min).
    async fn apns_jwt(&self) -> Option<String> {
        let cfg = self.apns.as_ref()?;
        let mut guard = self.apns_jwt.lock().await;
        let now = Utc::now().timestamp();
        if let Some((jwt, minted)) = guard.as_ref() {
            if now - minted < APNS_JWT_TTL_SECS {
                return Some(jwt.clone());
            }
        }
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(cfg.key_id.clone());
        let claims = json!({ "iss": cfg.team_id, "iat": now });
        let key = EncodingKey::from_ec_pem(&cfg.key_pem)
            .map_err(|e| tracing::warn!(error = %e, "bad APNs key"))
            .ok()?;
        let jwt = encode(&header, &claims, &key).ok()?;
        *guard = Some((jwt.clone(), now));
        Some(jwt)
    }

    /// Cached OAuth2 access token for FCM (service-account JWT grant).
    async fn fcm_access_token(&self, http: &reqwest::Client) -> Option<String> {
        let cfg = self.fcm.as_ref()?;
        let mut guard = self.fcm_token.lock().await;
        let now = Utc::now().timestamp();
        if let Some((tok, exp)) = guard.as_ref() {
            if now + FCM_TOKEN_SLACK_SECS < *exp {
                return Some(tok.clone());
            }
        }
        let claims = json!({
            "iss": cfg.client_email,
            "scope": "https://www.googleapis.com/auth/firebase.messaging",
            "aud": "https://oauth2.googleapis.com/token",
            "iat": now,
            "exp": now + 3600,
        });
        let key = EncodingKey::from_rsa_pem(cfg.private_key_pem.as_bytes())
            .map_err(|e| tracing::warn!(error = %e, "bad FCM service-account key"))
            .ok()?;
        let assertion = encode(&Header::new(Algorithm::RS256), &claims, &key).ok()?;
        let resp = http
            .post("https://oauth2.googleapis.com/token")
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await
            .ok()?;
        let v: serde_json::Value = resp.json().await.ok()?;
        let tok = v.get("access_token")?.as_str()?.to_string();
        let ttl = v.get("expires_in").and_then(|x| x.as_i64()).unwrap_or(3600);
        *guard = Some((tok.clone(), now + ttl));
        Some(tok)
    }
}

/// Delivery outcome, mirroring the web-push cases the fan-out already handles.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SendResult {
    Ok,
    /// Token is dead (uninstalled/expired) — deactivate it.
    Gone,
    Failed,
    /// Channel not configured — not an error.
    Skipped,
}

#[derive(Serialize)]
struct ApnsAlert<'a> {
    title: &'a str,
    body: &'a str,
}

pub async fn send_apns(state: &AppState, device_token: &str, payload: &PushPayload) -> SendResult {
    let Some(cfg) = state.native.apns.as_ref() else { return SendResult::Skipped };
    let Some(jwt) = state.native.apns_jwt().await else { return SendResult::Failed };

    let body = json!({
        "aps": {
            "alert": ApnsAlert { title: &payload.title, body: &payload.body },
            "sound": "default",
            "thread-id": payload.tag,
        },
        "url": payload.url,
    });
    let req = state
        .http
        .post(format!("{}/3/device/{}", cfg.endpoint, device_token))
        .bearer_auth(jwt)
        .header("apns-topic", &cfg.topic)
        .header("apns-push-type", "alert")
        .header("apns-priority", "10")
        .header("apns-collapse-id", collapse_id(&payload.tag))
        .json(&body);

    match crate::downstream::send("apns", req).await {
        Ok(resp) if resp.status().is_success() => SendResult::Ok,
        Ok(resp) if resp.status().as_u16() == 410 => SendResult::Gone,
        Ok(resp) => {
            // 400 BadDeviceToken also means the token is useless to us.
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            if text.contains("BadDeviceToken") || text.contains("Unregistered") {
                return SendResult::Gone;
            }
            tracing::warn!(%status, body = %text.chars().take(200).collect::<String>(), "APNs send failed");
            SendResult::Failed
        }
        Err(e) => {
            tracing::warn!(error = %e, "APNs transport error");
            SendResult::Failed
        }
    }
}

pub async fn send_fcm(state: &AppState, device_token: &str, payload: &PushPayload) -> SendResult {
    let Some(cfg) = state.native.fcm.as_ref() else { return SendResult::Skipped };
    let Some(token) = state.native.fcm_access_token(&state.http).await else {
        return SendResult::Failed;
    };

    let body = json!({
        "message": {
            "token": device_token,
            "notification": { "title": payload.title, "body": payload.body },
            "data": { "url": payload.url, "tag": payload.tag },
            "android": {
                "priority": "HIGH",
                "collapse_key": collapse_id(&payload.tag),
                "notification": { "tag": payload.tag }
            }
        }
    });
    let req = state
        .http
        .post(format!("https://fcm.googleapis.com/v1/projects/{}/messages:send", cfg.project_id))
        .bearer_auth(token)
        .json(&body);

    match crate::downstream::send("fcm", req).await {
        Ok(resp) if resp.status().is_success() => SendResult::Ok,
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            if status == 404 || text.contains("UNREGISTERED") || text.contains("INVALID_ARGUMENT") && text.contains("registration token") {
                return SendResult::Gone;
            }
            tracing::warn!(status, body = %text.chars().take(200).collect::<String>(), "FCM send failed");
            SendResult::Failed
        }
        Err(e) => {
            tracing::warn!(error = %e, "FCM transport error");
            SendResult::Failed
        }
    }
}
