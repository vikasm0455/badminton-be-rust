//! Client-IP extraction + a small in-memory per-IP rate limiter.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::async_trait;
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::HeaderMap;
use axum::http::request::Parts;

/// Extractor yielding the best-effort client IP for any handler.
#[derive(Debug, Clone, Copy)]
pub struct ClientIp(pub IpAddr);

#[async_trait]
impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0)
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        Ok(ClientIp(client_ip(&parts.headers, peer)))
    }
}

/// Best-effort client IP. Behind Cloudflare/Nginx, trust CF-Connecting-IP then
/// the first X-Forwarded-For hop; otherwise the socket peer.
pub fn client_ip(headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
    if let Some(ip) = headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse().ok())
    {
        return ip;
    }
    if let Some(ip) = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .and_then(|v| v.trim().parse().ok())
    {
        return ip;
    }
    peer.ip()
}

/// Fixed-window per-IP limiter (in-memory; resets on restart). Good enough for
/// a single-instance personal server.
pub struct RateLimiter {
    max_in_window: u32,
    window: Duration,
    hits: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl RateLimiter {
    pub fn new(max_in_window: u32, window: Duration) -> Self {
        Self {
            max_in_window,
            window,
            hits: Mutex::new(HashMap::new()),
        }
    }

    pub fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut hits = self.hits.lock().unwrap();
        if hits.len() > 10_000 {
            let window = self.window;
            hits.retain(|_, (start, _)| now.duration_since(*start) < window);
        }
        let entry = hits.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= self.max_in_window
    }
}
