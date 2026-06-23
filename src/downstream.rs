//! Wrapper for outbound HTTP calls that records dependency metrics (count by
//! status + latency). `dependency` is a stable label, e.g. "resend", "anthropic".

use std::time::Instant;

use crate::metrics;

pub async fn send(
    dependency: &str,
    req: reqwest::RequestBuilder,
) -> reqwest::Result<reqwest::Response> {
    let start = Instant::now();
    let result = req.send().await;
    let elapsed = start.elapsed().as_secs_f64();

    // reqwest only errors on transport failures (connect/timeout/decode); an
    // HTTP 4xx/5xx still returns Ok, so the real status is captured here.
    let status = match &result {
        Ok(resp) => resp.status().as_u16().to_string(),
        Err(_) => "error".to_string(),
    };
    metrics::record_downstream(dependency, &status, elapsed);
    result
}
