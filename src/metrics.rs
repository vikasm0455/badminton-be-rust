//! Prometheus metrics (mirrors rust-be-app). Exposed at the token-gated
//! `/metrics` endpoint. Instruments HTTP requests, outbound dependency calls
//! (Resend, Anthropic), and Web Push deliveries.

use lazy_static::lazy_static;
use prometheus::{CounterVec, Encoder, HistogramOpts, HistogramVec, Opts, Registry, TextEncoder};

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();

    pub static ref HTTP_REQUESTS_TOTAL: CounterVec = CounterVec::new(
        Opts::new("http_requests_total", "Total HTTP requests"),
        &["method", "endpoint", "status"]
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

    // Web Push deliveries, labeled by result: "ok" | "failed" | "gone".
    pub static ref PUSH_SENT_TOTAL: CounterVec = CounterVec::new(
        Opts::new("push_sent_total", "Web Push deliveries by result"),
        &["result"]
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
    });
}

/// Record one HTTP request's count and latency.
pub fn record_request(method: &str, endpoint: &str, status: u16, elapsed_secs: f64) {
    let status = status.to_string();
    HTTP_REQUESTS_TOTAL
        .with_label_values(&[method, endpoint, &status])
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

/// Record one Web Push delivery outcome.
pub fn record_push(result: &str) {
    PUSH_SENT_TOTAL.with_label_values(&[result]).inc();
}

pub fn metrics_handler() -> String {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap_or_default();
    String::from_utf8(buffer).unwrap_or_default()
}
