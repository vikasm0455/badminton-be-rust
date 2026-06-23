//! Transactional email via Resend. With no RESEND_API_KEY the message (and any
//! OTP code) is logged to the server console so flows are testable in dev.

use serde_json::json;

use crate::error::ApiError;
use crate::state::AppState;

async fn send_email(state: &AppState, to: &str, subject: &str, text: &str) -> Result<(), ApiError> {
    let Some(api_key) = &state.config.resend_api_key else {
        tracing::info!(email = to, subject, text, "RESEND_API_KEY not set — email logged");
        return Ok(());
    };

    let body = json!({
        "from": state.config.email_from,
        "to": [to],
        "subject": subject,
        "text": text,
    });

    let resp = state
        .http
        .post("https://api.resend.com/emails")
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to reach email provider");
            ApiError::EmailDelivery
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let detail = resp.text().await.unwrap_or_default();
        tracing::error!(%status, detail, "email provider rejected the send");
        return Err(ApiError::EmailDelivery);
    }
    Ok(())
}

pub async fn send_otp(state: &AppState, to: &str, code: &str) -> Result<(), ApiError> {
    send_email(
        state,
        to,
        "Your RallyUp verification code",
        &format!(
            "Your RallyUp code is {code}.\n\n\
             It expires in 5 minutes. If you didn't request this, you can ignore this email."
        ),
    )
    .await
}

pub async fn send_approved(state: &AppState, to: &str, name: &str) -> Result<(), ApiError> {
    send_email(
        state,
        to,
        "You're in! RallyUp access approved",
        &format!("Hi {name},\n\nYou've been approved! Open the app to play.\n\n— RallyUp"),
    )
    .await
}

pub async fn send_rejected(state: &AppState, to: &str, name: &str) -> Result<(), ApiError> {
    send_email(
        state,
        to,
        "RallyUp join request",
        &format!("Hi {name},\n\nSorry, your request was not approved.\n\n— RallyUp"),
    )
    .await
}

pub async fn send_reactivated(state: &AppState, to: &str, name: &str) -> Result<(), ApiError> {
    send_email(
        state,
        to,
        "Your RallyUp access has been restored",
        &format!("Hi {name},\n\nYour access has been restored. Please log in again.\n\n— RallyUp"),
    )
    .await
}
