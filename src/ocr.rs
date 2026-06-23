//! Credential screenshot OCR via Claude Vision (PRD §6.1.1). Always degrades
//! gracefully: on missing key, timeout, or unparseable output it returns empty
//! fields so the UI falls back to manual entry.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::json;

use crate::state::AppState;

pub struct OcrOutcome {
    pub name: String,
    pub password: String,
    /// true when the model returned at least one field; false → manual fallback.
    pub ok: bool,
}

const PROMPT: &str = "This is a photo of a Bintang Badminton kiosk screen. \
Extract the Name (shown in blue text) and the Password (shown in red text). \
Respond with ONLY a JSON object, no prose: {\"name\": \"...\", \"password\": \"...\"}. \
If a field is unreadable, use an empty string for it.";

pub async fn extract(state: &AppState, image: &[u8], media_type: &str) -> OcrOutcome {
    let empty = OcrOutcome { name: String::new(), password: String::new(), ok: false };

    let Some(api_key) = &state.config.anthropic_api_key else {
        tracing::info!("ANTHROPIC_API_KEY not set — OCR skipped, manual entry");
        return empty;
    };

    let media_type = if media_type == "image/png" { "image/png" } else { "image/jpeg" };
    let b64 = STANDARD.encode(image);

    let body = json!({
        "model": state.config.anthropic_model,
        "max_tokens": 256,
        "messages": [{
            "role": "user",
            "content": [
                { "type": "image", "source": { "type": "base64", "media_type": media_type, "data": b64 } },
                { "type": "text", "text": PROMPT }
            ]
        }]
    });

    let resp = state
        .http
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .timeout(std::time::Duration::from_secs(10)) // PRD §19.1: OCR caps at 10s
        .json(&body)
        .send()
        .await;

    let resp = match resp {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            tracing::warn!(status = %r.status(), "Claude Vision returned error status");
            return empty;
        }
        Err(e) => {
            tracing::warn!(error = %e, "Claude Vision request failed/timed out");
            return empty;
        }
    };

    let val: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "could not parse Claude response");
            return empty;
        }
    };

    // content[0].text holds the model's JSON string.
    let text = val
        .get("content")
        .and_then(|c| c.get(0))
        .and_then(|b| b.get("text"))
        .and_then(|t| t.as_str())
        .unwrap_or("");

    let parsed: serde_json::Value = serde_json::from_str(extract_json(text)).unwrap_or(json!({}));
    let name = parsed.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let password = parsed.get("password").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();

    let ok = !name.is_empty() || !password.is_empty();
    OcrOutcome { name, password, ok }
}

/// Pull the first {...} block out of a possibly-fenced response.
fn extract_json(s: &str) -> &str {
    let start = s.find('{');
    let end = s.rfind('}');
    match (start, end) {
        (Some(a), Some(b)) if b > a => &s[a..=b],
        _ => "{}",
    }
}
