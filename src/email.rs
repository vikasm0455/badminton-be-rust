//! Transactional email via Resend. Every message is sent as multipart HTML +
//! plain-text: the branded HTML renders in-client, the text part is the
//! fallback (and keeps spam scores sane). With no RESEND_API_KEY the message
//! (and any OTP code) is logged — recipient + subject only — so flows are
//! testable in dev without leaking secrets.
//!
//! Email HTML rules (why it looks the way it does): table-based layout, 100%
//! inline styles, no remote images (many clients block them — the logo is a
//! coloured cell + emoji), solid background colours so dark-mode inversion
//! stays readable, and bulletproof padded-<td> buttons that survive Outlook's
//! Word rendering engine.

use serde_json::json;

use crate::error::ApiError;
use crate::state::AppState;

const FONT: &str =
    "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";

/// HTML-escape a value interpolated into an email body. Club/group/inviter
/// names are user-controlled, so this is the injection guard — never drop a
/// raw value into the markup.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Shared logo header row (identical across every template).
fn header_row() -> String {
    format!(
        "<tr><td style=\"padding:28px 32px 8px 32px;\">\
<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\"><tr>\
<td width=\"36\" height=\"36\" bgcolor=\"#b06f3c\" style=\"background-color:#b06f3c;border-radius:9px;width:36px;height:36px;text-align:center;vertical-align:middle;font-size:18px;line-height:36px;\">&#127992;</td>\
<td style=\"padding-left:10px;font-family:{FONT};font-size:17px;font-weight:700;color:#1d2622;\">BadmintonRallyUp</td>\
</tr></table></td></tr>"
    )
}

/// Shared footer row.
fn footer_row() -> String {
    format!(
        "<tr><td style=\"padding:18px 32px 24px 32px;font-family:{FONT};\">\
<div style=\"font-size:12px;color:#5d6b64;\">BadmintonRallyUp &middot; badmintonrallyup.com</div>\
<div style=\"font-size:11px;color:#9aa5a0;padding-top:4px;\">You received this because of activity on your RallyUp account.</div>\
</td></tr>"
    )
}

/// Bulletproof green CTA button row + a paste-this-link fallback line.
fn button_rows(url: &str, label: &str) -> String {
    let u = esc(url);
    format!(
        "<tr><td align=\"center\" style=\"padding:24px 32px 4px 32px;\">\
<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\"><tr>\
<td align=\"center\" bgcolor=\"#1e8a52\" style=\"background-color:#1e8a52;border-radius:8px;padding:13px 28px;\">\
<a href=\"{u}\" style=\"display:inline-block;font-family:{FONT};font-size:15px;font-weight:700;line-height:18px;color:#ffffff;text-decoration:none;\">{label}</a>\
</td></tr></table></td></tr>\
<tr><td style=\"padding:14px 32px 24px 32px;font-family:{FONT};font-size:12px;color:#5d6b64;line-height:1.6;border-bottom:1px solid #eceeed;text-align:center;\">\
Button not working? Paste this into your browser: <a href=\"{u}\" style=\"color:#1e8a52;text-decoration:underline;word-break:break-all;\">{u}</a>\
</td></tr>"
    )
}

/// Wrap template-specific content rows in the full email document.
fn document(content_rows: &str) -> String {
    format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"></head>\
<body style=\"margin:0;padding:0;\">\
<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"background-color:#f3f5f4;\">\
<tr><td align=\"center\" style=\"padding:24px 12px;\">\
<table role=\"presentation\" width=\"600\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"max-width:600px;width:100%;background-color:#ffffff;border-radius:10px;\">\
{}{}{}\
</table></td></tr></table></body></html>",
        header_row(),
        content_rows,
        footer_row(),
    )
}

/// A plain heading + paragraph content block (the common case).
fn heading_block(heading_html: &str, body_html: &str) -> String {
    format!(
        "<tr><td style=\"padding:20px 32px 0 32px;font-family:{FONT};\">\
<div style=\"font-size:20px;font-weight:700;color:#1d2622;line-height:1.35;\">{heading_html}</div>\
<div style=\"font-size:15px;color:#3d4a44;line-height:1.6;padding-top:10px;\">{body_html}</div>\
</td></tr>"
    )
}

async fn send_email(
    state: &AppState,
    to: &str,
    subject: &str,
    text: &str,
    html: Option<&str>,
) -> Result<(), ApiError> {
    let Some(api_key) = &state.config.resend_api_key else {
        // Recipient + subject only: bodies carry OTP codes and temp passwords,
        // which must never land in server logs.
        tracing::info!(email = to, subject, "RESEND_API_KEY not set — email suppressed (body redacted)");
        return Ok(());
    };

    let mut body = json!({
        "from": state.config.email_from,
        "to": [to],
        "subject": subject,
        "text": text,
    });
    if let Some(html) = html {
        body["html"] = json!(html);
    }

    let req = state
        .http
        .post("https://api.resend.com/emails")
        .bearer_auth(api_key)
        .json(&body);
    let resp = crate::downstream::send("resend", req).await.map_err(|e| {
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
    let content = format!(
        "{}\
<tr><td style=\"padding:20px 32px 0 32px;\">\
<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\"><tr>\
<td align=\"center\" style=\"background-color:#faf6f1;border:1px solid #e8ddd1;border-radius:10px;padding:22px 16px;\">\
<span style=\"font-family:Consolas,Menlo,monospace;font-size:32px;font-weight:700;letter-spacing:10px;color:#b06f3c;\">{code}</span>\
</td></tr></table></td></tr>\
<tr><td style=\"padding:14px 32px 0 32px;font-family:{FONT};font-size:13px;color:#5d6b64;line-height:1.6;\">This code expires in <strong style=\"color:#1d2622;\">5 minutes</strong>.</td></tr>\
<tr><td style=\"padding:16px 32px 28px 32px;font-family:{FONT};font-size:13px;color:#5d6b64;line-height:1.6;border-bottom:1px solid #eceeed;\">Didn't try to sign in? You can safely ignore this email &mdash; nobody gets in without the code.</td></tr>",
        heading_block("Your sign-in code", "Type this into RallyUp and you're in."),
        code = esc(code),
    );
    send_email(
        state,
        to,
        "Your RallyUp sign-in code",
        &format!(
            "Your RallyUp code is {code}.\n\n\
             It expires in 5 minutes. If you didn't request this, you can ignore this email."
        ),
        Some(&document(&content)),
    )
    .await
}

/// Courts onboarding: mail the club admin their sign-in email + temp password.
pub async fn send_club_admin_invite(
    state: &AppState,
    to: &str,
    club_name: &str,
    slug: &str,
    temp_password: &str,
) -> Result<(), ApiError> {
    let base = state
        .config
        .app_base_url
        .as_deref()
        .unwrap_or("https://badmintonrallyup.com");
    let admin_url = format!("{base}/courts/{slug}/admin");
    let kiosk_url = format!("{base}/courts/{slug}");

    let step = |n: &str, txt: &str| {
        format!(
            "<tr>\
<td width=\"26\" valign=\"top\" style=\"padding-bottom:10px;\"><span style=\"display:inline-block;width:20px;height:20px;line-height:20px;text-align:center;background-color:#1e8a52;color:#ffffff;border-radius:10px;font-size:12px;font-weight:700;font-family:{FONT};\">{n}</span></td>\
<td style=\"padding-bottom:10px;font-family:{FONT};font-size:14px;color:#3d4a44;line-height:1.5;\">{txt}</td></tr>"
        )
    };
    let content = format!(
        "{heading}\
<tr><td style=\"padding:20px 32px 0 32px;\">\
<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\"><tr>\
<td style=\"background-color:#faf6f1;border:1px solid #e8ddd1;border-radius:10px;padding:16px 20px;\">\
<div style=\"font-family:{FONT};font-size:11px;font-weight:700;letter-spacing:.08em;color:#8a6a4b;\">TEMPORARY PASSWORD</div>\
<div style=\"font-family:Consolas,Menlo,monospace;font-size:20px;font-weight:700;letter-spacing:2px;color:#1d2622;padding-top:6px;\">{pw}</div>\
</td></tr></table></td></tr>\
<tr><td style=\"padding:20px 32px 0 32px;font-family:{FONT};\">\
<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\">{s1}{s2}{s3}</table></td></tr>\
{button}",
        heading = heading_block(
            &esc(club_name),
            "You're the admin. Your club's court booking is set up and waiting &mdash; here's how to take the keys.",
        ),
        pw = esc(temp_password),
        s1 = step("1", "Sign in at your admin link with the password above"),
        s2 = step("2", "Set a real password &mdash; the temporary one is single-use"),
        s3 = step("3", "Add your members and open up the courts"),
        button = button_rows(&admin_url, "Open your admin console"),
    );
    send_email(
        state,
        to,
        &format!("{club_name} is ready — you're the admin"),
        &format!(
            "Hi,\n\n\
             Your club \"{club_name}\" is set up on RallyUp Courts and you're the admin.\n\n\
             Admin console: {admin_url}\n\
             Sign in with this email address and the temporary password below — \
             you'll choose your own on first login.\n\n\
             Temporary password: {temp_password}\n\n\
             Kiosk board (share with the front desk): {kiosk_url}\n\n\
             — RallyUp Courts"
        ),
        Some(&document(&content)),
    )
    .await
}

pub async fn send_group_invite(
    state: &AppState,
    to: &str,
    group_name: &str,
    inviter: &str,
) -> Result<(), ApiError> {
    let base = state.config.app_base_url.as_deref().unwrap_or("");
    let heading = format!(
        "{} invited you to <span style=\"color:#1e8a52;\">{}</span>",
        esc(inviter),
        esc(group_name)
    );
    let intro = "RallyUp is where the group plans sessions, splits into courts, and keeps score &mdash; one tap to say you're playing.";
    // With a real base URL, show the button; otherwise a plain instruction.
    let tail = if base.is_empty() {
        format!(
            "<tr><td style=\"padding:16px 32px 24px 32px;font-family:{FONT};font-size:14px;color:#3d4a44;line-height:1.6;border-bottom:1px solid #eceeed;\">Sign up (or log in) with this email address in the RallyUp app and you'll see the invite waiting.</td></tr>"
        )
    } else {
        button_rows(base, "Join the group")
    };
    let content = format!("{}{}", heading_block(&heading, intro), tail);

    let link = if base.is_empty() { "the RallyUp app".to_string() } else { base.to_string() };
    send_email(
        state,
        to,
        &format!("{inviter} invited you to {group_name} on RallyUp"),
        &format!(
            "{inviter} invited you to join the badminton group “{group_name}” on RallyUp.\n\n\
             Sign up (or log in) with this email address at {link} and you'll see the invite waiting.\n\n\
             — RallyUp"
        ),
        Some(&document(&content)),
    )
    .await
}

fn app_button_or_note(base: &str) -> String {
    if base.is_empty() {
        format!(
            "<tr><td style=\"padding:8px 32px 24px 32px;font-family:{FONT};font-size:13px;color:#5d6b64;line-height:1.6;border-bottom:1px solid #eceeed;\">Open the RallyUp app to play.</td></tr>"
        )
    } else {
        format!(
            "<tr><td align=\"center\" style=\"padding:24px 32px 24px 32px;border-bottom:1px solid #eceeed;\">\
<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\"><tr>\
<td align=\"center\" bgcolor=\"#1e8a52\" style=\"background-color:#1e8a52;border-radius:8px;padding:13px 28px;\">\
<a href=\"{u}\" style=\"display:inline-block;font-family:{FONT};font-size:15px;font-weight:700;line-height:18px;color:#ffffff;text-decoration:none;\">Open RallyUp</a>\
</td></tr></table></td></tr>",
            u = esc(base)
        )
    }
}

// LEGACY-SINGLE-TENANT: only used by the dead approve/reject flow — delete with it.
pub async fn send_approved(state: &AppState, to: &str, name: &str) -> Result<(), ApiError> {
    let base = state.config.app_base_url.as_deref().unwrap_or("");
    let content = format!(
        "{}{}",
        heading_block(
            &format!("You're in, {} &#127881;", esc(name)),
            "Your request was approved. Sessions, courts, and scores are all open to you now &mdash; see you on court.",
        ),
        app_button_or_note(base),
    );
    send_email(
        state,
        to,
        "You're in — RallyUp access approved",
        &format!("Hi {name},\n\nYou've been approved! Open the app to play.\n\n— RallyUp"),
        Some(&document(&content)),
    )
    .await
}

// LEGACY-SINGLE-TENANT: only used by the dead approve/reject flow — delete with it.
pub async fn send_rejected(state: &AppState, to: &str, name: &str) -> Result<(), ApiError> {
    // Deliberately gentle and button-free; the subject avoids "rejected".
    let content = format!(
        "<tr><td style=\"padding:20px 32px 24px 32px;font-family:{FONT};border-bottom:1px solid #eceeed;\">\
<div style=\"font-size:18px;font-weight:700;color:#1d2622;line-height:1.35;\">About your RallyUp join request</div>\
<div style=\"font-size:15px;color:#3d4a44;line-height:1.6;padding-top:10px;\">Hi {name} &mdash; the organizer decided not to add you right now. That can happen for lots of reasons, often just group size.</div>\
<div style=\"font-size:14px;color:#5d6b64;line-height:1.6;padding-top:10px;\">If you think it's a mix-up, the best route is to reach the organizer directly. Nothing else is needed from you.</div>\
</td></tr>",
        name = esc(name),
    );
    send_email(
        state,
        to,
        "About your RallyUp join request",
        &format!(
            "Hi {name},\n\nThe organizer decided not to add you right now — often that's just group size. \
             If you think it's a mix-up, reach the organizer directly.\n\n— RallyUp"
        ),
        Some(&document(&content)),
    )
    .await
}

pub async fn send_reactivated(state: &AppState, to: &str, name: &str) -> Result<(), ApiError> {
    let base = state.config.app_base_url.as_deref().unwrap_or("");
    let content = format!(
        "{}{}",
        heading_block(
            &format!("Welcome back, {}", esc(name)),
            "Your RallyUp access is active again. Everything's where you left it &mdash; sessions, your stats, the lot. Grab your racket.",
        ),
        app_button_or_note(base),
    );
    send_email(
        state,
        to,
        "Welcome back to RallyUp",
        &format!("Hi {name},\n\nYour access has been restored. Please log in again.\n\n— RallyUp"),
        Some(&document(&content)),
    )
    .await
}

/// Guideline 1.2: content reports and user blocks must notify the developer.
/// Best-effort — moderation rows are stored regardless of email delivery.
/// Internal-only, so it stays plain text (no branding needed).
pub async fn send_moderation_alert(state: &AppState, subject: &str, text: &str) {
    let to = state.config.moderation_notify_email.clone();
    if let Err(e) = send_email(state, &to, subject, text, None).await {
        tracing::error!(error = %e, "moderation alert email failed (report/block still stored)");
    }
}
