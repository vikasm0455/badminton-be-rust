//! Shared multipart image reader for the credential-OCR and board-scan uploads.
//!
//! Reads the `image` field with a hard byte cap, validating the content type
//! BEFORE buffering. Crucially, on any rejection it DRAINS the rest of the
//! still-uploading request body before returning, so the connection closes
//! cleanly. Without this, the server responds and closes mid-upload, and the
//! reverse proxy reports "upstream prematurely closed connection" → 502.
//!
//! For this to work the global `DefaultBodyLimit` must sit comfortably above
//! `max_bytes` (see lib.rs), so the cap below trips first and the drain stays
//! within the body limit.

use axum::extract::Multipart;
use axum::extract::multipart::Field;

use crate::error::ApiError;

/// Pull the `image` field's bytes (+ content type), capped at `max_bytes`.
pub async fn read_image_field(
    mut multipart: Multipart,
    max_bytes: usize,
) -> Result<(Vec<u8>, String), ApiError> {
    let mut found: Option<(Vec<u8>, String)> = None;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::BadRequest(format!("invalid upload: {e}")))?
    {
        if field.name() != Some("image") {
            drain_field(&mut field).await;
            continue;
        }

        let content_type = field.content_type().unwrap_or("image/jpeg").to_string();
        if content_type != "image/jpeg" && content_type != "image/png" {
            drain_field(&mut field).await;
            drain_rest(&mut multipart).await;
            return Err(ApiError::BadRequest("Only JPEG or PNG photos are accepted.".into()));
        }

        let mut buf: Vec<u8> = Vec::new();
        let mut too_big = false;
        loop {
            match field.chunk().await {
                Ok(Some(chunk)) => {
                    if buf.len() + chunk.len() > max_bytes {
                        too_big = true;
                        break;
                    }
                    buf.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                // Stream error (e.g. the global body limit tripped) — stop reading.
                Err(_) => break,
            }
        }

        if too_big {
            drain_field(&mut field).await;
            drain_rest(&mut multipart).await;
            return Err(ApiError::PayloadTooLarge(
                "Photo too large — retake or enter manually.".into(),
            ));
        }

        found = Some((buf, content_type));
    }

    found.ok_or_else(|| ApiError::BadRequest("no image provided".into()))
}

async fn drain_field(field: &mut Field<'_>) {
    while matches!(field.chunk().await, Ok(Some(_))) {}
}

async fn drain_rest(multipart: &mut Multipart) {
    while let Ok(Some(mut f)) = multipart.next_field().await {
        drain_field(&mut f).await;
    }
}
