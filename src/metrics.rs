//! Prometheus metrics (mirrors rust-be-app). Exposed at the token-gated
//! `/metrics` endpoint. Instruments HTTP requests, outbound dependency calls
//! (Resend, Anthropic), Web Push deliveries, product feature events, OCR scan
//! outcomes, and sampled gauges (active users, DB pool, process/CPU).

use lazy_static::lazy_static;
use prometheus::{
    CounterVec, Encoder, HistogramOpts, HistogramVec, IntGauge, IntGaugeVec, Opts, Registry,
    TextEncoder,
};
use redis::AsyncCommands;

use crate::state::AppState;

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();

    pub static ref HTTP_REQUESTS_TOTAL: CounterVec = CounterVec::new(
        Opts::new("http_requests_total", "Total HTTP requests"),
        &["method", "endpoint", "status", "client"]
    ).unwrap();

    pub static ref HTTP_REQUEST_DURATION: HistogramVec = HistogramVec::new(
        HistogramOpts::new("http_request_duration_seconds", "HTTP request duration"),
        &["method", "endpoint"]
    ).unwrap();

    // Outbound dependency calls: "resend" (email OTP), "anthropic" (OCR).
    // Labeled by dependency and response status (or "error" on transport failure).
    pub static ref DOWNSTREAM_REQUESTS_TOTAL: CounterVec = CounterVec::new(
        Opts::new("downstream_requests_total", "Outbound dependency requests by status"),
        &["dependency", "status"]
    ).unwrap();

    pub static ref DOWNSTREAM_REQUEST_DURATION: HistogramVec = HistogramVec::new(
        HistogramOpts::new("downstream_request_duration_seconds", "Outbound dependency latency"),
        &["dependency"]
    ).unwrap();

    // Push deliveries by platform ("web" | "apns" | "fcm") and result
    // ("ok" | "failed" | "gone").
    pub static ref PUSH_SENT_TOTAL: CounterVec = CounterVec::new(
        Opts::new("push_sent_total", "Push deliveries by platform and result"),
        &["platform", "result"]
    ).unwrap();

    // Refresh-token rotation outcomes — the native-session security signal.
    // result: ok | grace | race_grace | reuse_revoked | rejected
    pub static ref TOKEN_REFRESH_TOTAL: CounterVec = CounterVec::new(
        Opts::new("token_refresh_total", "Refresh-token rotation outcomes"),
        &["result"]
    ).unwrap();

    // Product usage by feature event and client (web | native). One counter,
    // one label pair — every new feature MUST record its key action here.
    pub static ref FEATURE_EVENTS_TOTAL: CounterVec = CounterVec::new(
        Opts::new("feature_events_total", "Key product actions by event and client"),
        &["event", "client"]
    ).unwrap();

    // Distinct authenticated users over trailing windows ("1d" | "7d"), split
    // by client ("native" | "web"). Sampled every 60s from the Redis daily
    // sets the auth extractor writes ("dau:<date>:<client>").
    pub static ref ACTIVE_USERS: IntGaugeVec = IntGaugeVec::new(
        Opts::new("active_users", "Distinct authenticated users by window and client"),
        &["window", "client"]
    ).unwrap();

    // OCR scans by kind ("board" | "login") and outcome
    // ("matched" | "no_match" | "error").
    pub static ref OCR_SCANS_TOTAL: CounterVec = CounterVec::new(
        Opts::new("ocr_scans_total", "OCR scans by kind and outcome"),
        &["kind", "outcome"]
    ).unwrap();

    // sqlx Postgres pool, sampled every 60s: state = "size" | "idle" | "max".
    pub static ref DB_POOL_CONNECTIONS: IntGaugeVec = IntGaugeVec::new(
        Opts::new("db_pool_connections", "Postgres pool connections by state"),
        &["state"]
    ).unwrap();

    // Static: logical cores available to the process (set once at startup) —
    // the ceiling for process_cpu_seconds_total rate charts.
    pub static ref SYSTEM_CPU_CORES: IntGauge = IntGauge::new(
        "system_cpu_cores", "Logical CPU cores available to the process"
    ).unwrap();
}

/// Register all collectors exactly once per process (idempotent — safe to call
/// from build_app even when many test apps are built).
pub fn register_metrics() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        REGISTRY.register(Box::new(HTTP_REQUESTS_TOTAL.clone())).ok();
        REGISTRY.register(Box::new(HTTP_REQUEST_DURATION.clone())).ok();
        REGISTRY.register(Box::new(DOWNSTREAM_REQUESTS_TOTAL.clone())).ok();
        REGISTRY.register(Box::new(DOWNSTREAM_REQUEST_DURATION.clone())).ok();
        REGISTRY.register(Box::new(PUSH_SENT_TOTAL.clone())).ok();
        REGISTRY.register(Box::new(TOKEN_REFRESH_TOTAL.clone())).ok();
        REGISTRY.register(Box::new(FEATURE_EVENTS_TOTAL.clone())).ok();
        REGISTRY.register(Box::new(ACTIVE_USERS.clone())).ok();
        REGISTRY.register(Box::new(OCR_SCANS_TOTAL.clone())).ok();
        REGISTRY.register(Box::new(DB_POOL_CONNECTIONS.clone())).ok();
        REGISTRY.register(Box::new(SYSTEM_CPU_CORES.clone())).ok();
        // Standard process_* collectors (CPU, RSS, fds, threads…). The crate
        // only implements them on Linux — which is where prod runs; dev macOS
        // simply goes without.
        #[cfg(target_os = "linux")]
        REGISTRY
            .register(Box::new(prometheus::process_collector::ProcessCollector::for_self()))
            .ok();
        SYSTEM_CPU_CORES.set(
            std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0) as i64,
        );
    });
}

/// Record one HTTP request's count and latency.
pub fn record_request(method: &str, endpoint: &str, status: u16, elapsed_secs: f64, client: &str) {
    let status = status.to_string();
    HTTP_REQUESTS_TOTAL
        .with_label_values(&[method, endpoint, &status, client])
        .inc();
    HTTP_REQUEST_DURATION
        .with_label_values(&[method, endpoint])
        .observe(elapsed_secs);
}

/// Record one outbound dependency call's count (by status) and latency.
pub fn record_downstream(dependency: &str, status: &str, elapsed_secs: f64) {
    DOWNSTREAM_REQUESTS_TOTAL
        .with_label_values(&[dependency, status])
        .inc();
    DOWNSTREAM_REQUEST_DURATION
        .with_label_values(&[dependency])
        .observe(elapsed_secs);
}

/// Record one push delivery outcome for a platform (web | apns | fcm).
pub fn record_push(platform: &str, result: &str) {
    PUSH_SENT_TOTAL.with_label_values(&[platform, result]).inc();
}

/// Record one refresh-token rotation outcome.
pub fn record_token_refresh(result: &str) {
    TOKEN_REFRESH_TOTAL.with_label_values(&[result]).inc();
}

/// Record a key product action (feature_events_total). `client` is
/// "native" when the request carried `X-Client: native`, else "web".
pub fn record_feature(event: &str, client: &str) {
    FEATURE_EVENTS_TOTAL.with_label_values(&[event, client]).inc();
}

/// Record one OCR scan outcome. kind: "board" | "login";
/// outcome: "matched" | "no_match" | "error".
pub fn record_ocr_scan(kind: &str, outcome: &str) {
    OCR_SCANS_TOTAL.with_label_values(&[kind, outcome]).inc();
}

/// Spawn the 60s gauge sampler (pool state + active-user windows). Called once
/// from main — not build_app, so test apps don't each spawn a loop.
pub fn spawn_samplers(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await; // first tick is immediate → gauges set at boot
            sample_db_pool(&state);
            sample_active_users(&state).await;
        }
    });
}

fn sample_db_pool(state: &AppState) {
    let pool = &state.db;
    DB_POOL_CONNECTIONS.with_label_values(&["size"]).set(pool.size() as i64);
    DB_POOL_CONNECTIONS.with_label_values(&["idle"]).set(pool.num_idle() as i64);
    DB_POOL_CONNECTIONS
        .with_label_values(&["max"])
        .set(pool.options().get_max_connections() as i64);
}

/// SCARD today's per-client set for the 1d window; SUNION the trailing 7 daily
/// sets for 7d. Best effort — gauges just go stale when Redis is down.
async fn sample_active_users(state: &AppState) {
    let Some(redis) = &state.redis else { return };
    let today = crate::time::today();
    for client in ["native", "web"] {
        let mut redis = redis.clone();
        if let Ok(n) = redis.scard::<_, i64>(format!("dau:{today}:{client}")).await {
            ACTIVE_USERS.with_label_values(&["1d", client]).set(n);
        }
        let week: Vec<String> = (0..7)
            .map(|d| format!("dau:{}:{client}", today - chrono::Duration::days(d)))
            .collect();
        if let Ok(users) = redis.sunion::<_, Vec<String>>(&week).await {
            ACTIVE_USERS.with_label_values(&["7d", client]).set(users.len() as i64);
        }
    }
}

pub fn metrics_handler() -> String {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap_or_default();
    String::from_utf8(buffer).unwrap_or_default()
}
