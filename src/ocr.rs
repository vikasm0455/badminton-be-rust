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

    let req = state
        .http
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .timeout(std::time::Duration::from_secs(10)) // PRD §19.1: OCR caps at 10s
        .json(&body);
    let resp = crate::downstream::send("anthropic", req).await;

    let resp = match resp {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            // Log Anthropic's error body (model-not-found, invalid key, low credit,
            // etc.) so the real reason is visible, not just the status code.
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            let body: String = body.chars().take(600).collect();
            tracing::warn!(%status, body = %body, "Claude Vision returned error status");
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

// ---- court status board OCR -------------------------------------------------

/// One court panel parsed off the facility status board.
#[derive(Debug, Clone)]
pub struct BoardCourt {
    pub court_number: i16,
    /// "Minutes Left" reading for the current group, if shown.
    pub minutes_left: Option<i16>,
    /// Names on the "Current Players" line.
    pub current_players: Vec<String>,
    /// Names from the numbered "Queue" list, in order.
    pub queue: Vec<String>,
}

const BOARD_PROMPT: &str = "This is a photo of the Bintang Badminton facility court status board. \
Each court panel shows a court number, a 'Minutes Left' number, a 'Current Players' line, and a numbered 'Queue'. \
For EVERY court panel you can read, extract: court_number (integer), minutes_left (integer, or null if not shown), \
current_players (array of the individual player names on the Current Players line, splitting on dashes/commas), \
and queue (array of the individual player names from the numbered queue list, in order). \
Respond with ONLY a JSON array and nothing else, e.g. \
[{\"court_number\":9,\"minutes_left\":19,\"current_players\":[\"Eric\",\"Eugene\"],\"queue\":[\"Younw\",\"Aishi\"]}]. \
Skip any panel where you cannot read the court number.";

/// OCR the whole status board into a list of court panels. Degrades to an empty
/// list (manual entry) on missing key, timeout, or unparseable output.
pub async fn extract_board(state: &AppState, image: &[u8], media_type: &str) -> Vec<BoardCourt> {
    let Some(api_key) = &state.config.anthropic_api_key else {
        tracing::info!("ANTHROPIC_API_KEY not set — board scan skipped, manual entry");
        return Vec::new();
    };

    let media_type = if media_type == "image/png" { "image/png" } else { "image/jpeg" };
    let b64 = STANDARD.encode(image);

    let body = json!({
        "model": state.config.anthropic_model,
        "max_tokens": 1500, // many courts per board → more room than the single-credential prompt
        "messages": [{
            "role": "user",
            "content": [
                { "type": "image", "source": { "type": "base64", "media_type": media_type, "data": b64 } },
                { "type": "text", "text": BOARD_PROMPT }
            ]
        }]
    });

    let req = state
        .http
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .timeout(std::time::Duration::from_secs(20)) // denser image than the kiosk OCR
        .json(&body);

    let resp = match crate::downstream::send("anthropic", req).await {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            tracing::warn!(status = %r.status(), "board OCR returned error status");
            return Vec::new();
        }
        Err(e) => {
            tracing::warn!(error = %e, "board OCR request failed/timed out");
            return Vec::new();
        }
    };

    let val: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "could not parse board OCR response");
            return Vec::new();
        }
    };

    let text = val
        .get("content")
        .and_then(|c| c.get(0))
        .and_then(|b| b.get("text"))
        .and_then(|t| t.as_str())
        .unwrap_or("");
    parse_board(text)
}

fn parse_board(text: &str) -> Vec<BoardCourt> {
    let arr: serde_json::Value = serde_json::from_str(extract_json_array(text)).unwrap_or(json!([]));
    let Some(items) = arr.as_array() else { return Vec::new() };
    let mut out = Vec::new();
    for it in items {
        let Some(court) = it.get("court_number").and_then(|v| v.as_i64()) else { continue };
        if !(1..=53).contains(&court) {
            continue;
        }
        out.push(BoardCourt {
            court_number: court as i16,
            minutes_left: it
                .get("minutes_left")
                .and_then(|v| v.as_i64())
                .map(|m| m.clamp(0, 240) as i16),
            current_players: str_array(it.get("current_players")),
            queue: str_array(it.get("queue")),
        });
    }
    out
}

fn str_array(v: Option<&serde_json::Value>) -> Vec<String> {
    v.and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Pull the first [...] block out of a possibly-fenced response.
fn extract_json_array(s: &str) -> &str {
    let start = s.find('[');
    let end = s.rfind(']');
    match (start, end) {
        (Some(a), Some(b)) if b > a => &s[a..=b],
        _ => "[]",
    }
}
