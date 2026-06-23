use axum::Json;
use axum::extract::{Multipart, Path, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{AdminUser, AuthUser};
use crate::error::ApiError;
use crate::models::ApiResponse;
use crate::state::{AppState, LiveEvent};
use crate::{notify, ocr, security, time};
use crate::security::event;

#[derive(Serialize, sqlx::FromRow)]
pub struct CredentialView {
    pub id: Uuid,
    pub bintang_name: String,
    pub bintang_password: String,
    pub posted_by: Uuid,
    pub posted_by_name: String,
    pub posted_at: DateTime<Utc>,
    pub has_screenshot: bool,
    /// Locked by an active, non-expired reservation.
    pub in_use: bool,
    pub in_use_court: Option<i16>,
    /// When today's credentials are auto-cleared (next 23:59 LA), as UTC.
    pub clears_at: DateTime<Utc>,
}

pub async fn today(
    State(state): State<AppState>,
    _user: AuthUser,
) -> Result<Json<ApiResponse<Vec<CredentialView>>>, ApiError> {
    let game_date = time::today();
    let clears_at = time::la_datetime_to_utc(
        game_date,
        chrono::NaiveTime::from_hms_opt(23, 59, 0).unwrap(),
    );

    let rows: Vec<(Uuid, String, String, Uuid, String, DateTime<Utc>, Option<String>, Option<i16>)> =
        sqlx::query_as(
            "SELECT c.id, c.bintang_name, c.bintang_password, c.posted_by,
                    u.display_name, c.posted_at, c.screenshot_path,
                    (SELECT r.court_number FROM court_reservations r
                       WHERE r.credential_id = c.id AND r.status = 'active' AND r.expiry_at > NOW()
                       ORDER BY r.start_at DESC LIMIT 1) AS in_use_court
             FROM court_credentials c JOIN users u ON u.id = c.posted_by
             WHERE c.game_date = $1
             ORDER BY c.posted_at ASC",
        )
        .bind(game_date)
        .fetch_all(&state.db)
        .await?;

    let cards = rows
        .into_iter()
        .map(|(id, name, pass, posted_by, posted_by_name, posted_at, shot, court)| CredentialView {
            id,
            bintang_name: name,
            bintang_password: pass,
            posted_by,
            posted_by_name,
            posted_at,
            has_screenshot: shot.is_some(),
            in_use: court.is_some(),
            in_use_court: court,
            clears_at,
        })
        .collect();
    Ok(Json(ApiResponse::ok(cards)))
}

#[derive(Deserialize)]
pub struct PostCredentialReq {
    pub bintang_name: String,
    pub bintang_password: String,
    /// Optional screenshot path returned by the /ocr endpoint.
    pub screenshot_path: Option<String>,
}

pub async fn post_credential(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<PostCredentialReq>,
) -> Result<Json<ApiResponse<CredentialView>>, ApiError> {
    let name = req.bintang_name.trim();
    let pass = req.bintang_password.trim();
    if name.is_empty() || name.len() > 50 || pass.is_empty() || pass.len() > 50 {
        return Err(ApiError::BadRequest("name and password are required (max 50 chars)".into()));
    }
    // Only accept a screenshot path we actually created for today.
    let screenshot = req
        .screenshot_path
        .as_deref()
        .filter(|p| p.starts_with(&creds_dir(&state, time::today())));

    let id: (Uuid,) = sqlx::query_as(
        "INSERT INTO court_credentials (posted_by, game_date, bintang_name, bintang_password, screenshot_path)
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(user.id)
    .bind(time::today())
    .bind(name)
    .bind(pass)
    .bind(screenshot)
    .fetch_one(&state.db)
    .await?;

    security::log(&state, event::CREDENTIAL_POSTED, Some(user.id), None, serde_json::json!({})).await;
    state.broadcast(LiveEvent::CredentialsChanged);

    let poster_name: (String,) = sqlx::query_as("SELECT display_name FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&state.db)
        .await?;
    notify::credential_posted(&state, user.id, &poster_name.0);

    let cards = today(State(state.clone()), user).await?;
    let card = cards
        .0
        .data
        .unwrap_or_default()
        .into_iter()
        .find(|c| c.id == id.0)
        .ok_or(ApiError::NotFound)?;
    Ok(Json(ApiResponse::ok(card)))
}

#[derive(Serialize)]
pub struct OcrResult {
    pub bintang_name: String,
    pub bintang_password: String,
    pub ok: bool,
    pub screenshot_path: Option<String>,
    pub message: String,
}

/// Accept a screenshot (multipart field "image"), OCR it, and stash the file.
pub async fn ocr_credential(
    State(state): State<AppState>,
    user: AuthUser,
    mut multipart: Multipart,
) -> Result<Json<ApiResponse<OcrResult>>, ApiError> {
    let max_bytes = state.config.max_upload_size_mb * 1024 * 1024;
    let mut image: Option<(Vec<u8>, String)> = None;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        ApiError::BadRequest(format!("invalid upload: {e}"))
    })? {
        if field.name() == Some("image") {
            let content_type = field.content_type().unwrap_or("image/jpeg").to_string();
            let data = field.bytes().await.map_err(|_| {
                ApiError::BadRequest("Photo too large (max 10MB). Retake or enter manually.".into())
            })?;
            if data.len() > max_bytes {
                return Err(ApiError::BadRequest(
                    "Photo too large (max 10MB). Retake or enter manually.".into(),
                ));
            }
            if content_type != "image/jpeg" && content_type != "image/png" {
                return Err(ApiError::BadRequest("Only JPEG or PNG photos are accepted.".into()));
            }
            image = Some((data.to_vec(), content_type));
        }
    }
    let (bytes, content_type) = image.ok_or_else(|| ApiError::BadRequest("no image provided".into()))?;

    // Persist the screenshot (cleared nightly with the credential).
    let dir = creds_dir(&state, time::today());
    let ext = if content_type == "image/png" { "png" } else { "jpg" };
    let rel_path = format!("{dir}/{}.{ext}", Uuid::new_v4());
    if let Err(e) = tokio::fs::create_dir_all(&dir).await {
        tracing::warn!(error = %e, "could not create uploads dir");
    }
    let screenshot_path = match tokio::fs::write(&rel_path, &bytes).await {
        Ok(()) => Some(rel_path),
        Err(e) => {
            tracing::warn!(error = %e, "failed to store screenshot");
            None
        }
    };

    let outcome = ocr::extract(&state, &bytes, &content_type).await;
    let message = if outcome.ok {
        "Review the details below and confirm.".to_string()
    } else {
        "Couldn't read the screen clearly — please check and fill in manually.".to_string()
    };
    let _ = user; // upload attributed implicitly; auth gate is the point.

    Ok(Json(ApiResponse::ok(OcrResult {
        bintang_name: outcome.name,
        bintang_password: outcome.password,
        ok: outcome.ok,
        screenshot_path,
        message,
    })))
}

/// Stream a credential's screenshot to authenticated members.
pub async fn screenshot(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT screenshot_path FROM court_credentials WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
    let path = row.and_then(|r| r.0).ok_or(ApiError::NotFound)?;
    let bytes = tokio::fs::read(&path).await.map_err(|_| ApiError::NotFound)?;
    let ctype = if path.ends_with(".png") { "image/png" } else { "image/jpeg" };
    Ok(([(header::CONTENT_TYPE, ctype)], bytes).into_response())
}

pub async fn delete_credential(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT screenshot_path FROM court_credentials WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
    let path = row.ok_or(ApiError::NotFound)?.0;
    sqlx::query("DELETE FROM court_credentials WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;
    if let Some(p) = path {
        let _ = tokio::fs::remove_file(p).await;
    }
    security::log(&state, event::CREDENTIAL_DELETED, Some(admin.id), None, serde_json::json!({ "id": id })).await;
    state.broadcast(LiveEvent::CredentialsChanged);
    Ok(Json(ApiResponse::message("Credential deleted.")))
}

pub async fn clear_today(
    State(state): State<AppState>,
    admin: AdminUser,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let removed = crate::jobs::clear_credentials_for(&state, time::today()).await?;
    security::log(&state, event::ADMIN_ACTION, Some(admin.id), None, serde_json::json!({ "action": "clear_credentials", "removed": removed })).await;
    state.broadcast(LiveEvent::CredentialsChanged);
    Ok(Json(ApiResponse::ok(serde_json::json!({ "removed": removed }))))
}

/// Directory for a given game date's screenshots, relative to UPLOADS_PATH.
fn creds_dir(state: &AppState, date: chrono::NaiveDate) -> String {
    format!("{}/creds/{}", state.config.uploads_path.trim_end_matches('/'), date)
}
