use axum::Json;
use axum::extract::{Multipart, Path, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::models::ApiResponse;
use crate::routes::groups::{active_group, require_group_admin};
use crate::state::{AppState, LiveEvent};
use crate::{metrics, notify, ocr, security, time};
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
    /// Locked by an active, non-expired reservation (any group — the login is
    /// physically on a court regardless of who logged it).
    pub in_use: bool,
    pub in_use_court: Option<i16>,
    /// When today's credentials are auto-cleared (next 23:59 LA), as UTC.
    pub clears_at: DateTime<Utc>,
    /// The caller posted this login (can manage shares / delete it).
    pub is_mine: bool,
    /// Groups this login is shared with — populated only when is_mine.
    pub shared_group_ids: Vec<Uuid>,
    /// Name of the group whose court is using this login — revealed only when
    /// the viewer belongs to that group (the owner always does).
    pub in_use_group_name: Option<String>,
    /// In use by a group the viewer is NOT in — court/group withheld.
    pub in_use_elsewhere: bool,
}

/// Today's logins visible in the caller's ACTIVE group: everything shared with
/// that group, plus the caller's own posts (even if unshared here, so they can
/// still manage them).
#[derive(Deserialize)]
pub struct TodayQuery {
    /// "all" → logins from every group the caller belongs to (log-court flow).
    pub scope: Option<String>,
}

pub async fn today(
    State(state): State<AppState>,
    user: AuthUser,
    axum::extract::Query(q): axum::extract::Query<TodayQuery>,
) -> Result<Json<ApiResponse<Vec<CredentialView>>>, ApiError> {
    let all_groups = q.scope.as_deref() == Some("all");
    let scope_group = if all_groups { None } else { Some(active_group(&state, user.id).await?.group_id) };
    let game_date = time::today();
    let clears_at = time::la_datetime_to_utc(
        game_date,
        chrono::NaiveTime::from_hms_opt(23, 59, 0).unwrap(),
    );

    let rows: Vec<(Uuid, String, String, Uuid, String, DateTime<Utc>, Option<String>, Option<i16>, Option<Uuid>)> =
        sqlx::query_as(
            "SELECT c.id, c.bintang_name, c.bintang_password, c.posted_by,
                    u.display_name, c.posted_at, c.screenshot_path,
                    (SELECT r.court_number FROM court_reservations r
                       WHERE (r.credential_id = c.id
                              OR EXISTS (SELECT 1 FROM reservation_credentials rc
                                         WHERE rc.reservation_id = r.id AND rc.credential_id = c.id))
                         AND r.status = 'active' AND r.expiry_at > NOW()
                       ORDER BY r.start_at DESC LIMIT 1) AS in_use_court,
                    (SELECT r.group_id FROM court_reservations r
                       WHERE (r.credential_id = c.id
                              OR EXISTS (SELECT 1 FROM reservation_credentials rc
                                         WHERE rc.reservation_id = r.id AND rc.credential_id = c.id))
                         AND r.status = 'active' AND r.expiry_at > NOW()
                       ORDER BY r.start_at DESC LIMIT 1) AS in_use_group
             FROM court_credentials c JOIN users u ON u.id = c.posted_by
             WHERE c.game_date = $1
               AND (c.posted_by = $2
                    OR EXISTS (SELECT 1 FROM credential_shares s
                               WHERE s.credential_id = c.id
                                 AND ($3::uuid IS NULL OR s.group_id = $3)
                                 AND EXISTS (SELECT 1 FROM group_members gm
                                             WHERE gm.group_id = s.group_id AND gm.user_id = $2)))
               AND NOT EXISTS (SELECT 1 FROM user_blocks ub
                               WHERE ub.blocker_id = $2 AND ub.blocked_id = c.posted_by)
               AND NOT EXISTS (SELECT 1 FROM content_reports cr
                               WHERE cr.reporter_id = $2 AND cr.content_type = 'credential'
                                 AND cr.content_id = c.id)
             ORDER BY c.posted_at ASC",
        )
        .bind(game_date)
        .bind(user.id)
        .bind(scope_group)
        .fetch_all(&state.db)
        .await?;

    // Viewer's groups (id -> name) for in-use disclosure decisions.
    let my_groups: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT g.id, g.name FROM groups g JOIN group_members gm ON gm.group_id = g.id WHERE gm.user_id = $1",
    )
    .bind(user.id)
    .fetch_all(&state.db)
    .await?;

    // Share lists for the caller's own logins (one query for all of them).
    let mine: Vec<Uuid> = rows.iter().filter(|r| r.3 == user.id).map(|r| r.0).collect();
    let shares: Vec<(Uuid, Uuid)> = if mine.is_empty() {
        Vec::new()
    } else {
        sqlx::query_as(
            "SELECT credential_id, group_id FROM credential_shares WHERE credential_id = ANY($1)",
        )
        .bind(&mine)
        .fetch_all(&state.db)
        .await?
    };

    let cards = rows
        .into_iter()
        .map(|(id, name, pass, posted_by, posted_by_name, posted_at, shot, court, use_group)| {
            let is_mine = posted_by == user.id;
            let shared_group_ids: Vec<Uuid> = if is_mine {
                shares.iter().filter(|(c, _)| *c == id).map(|(_, g)| *g).collect()
            } else {
                Vec::new()
            };
            // Disclose the using group's court + name only to its members
            // (the owner is always a member of every group they shared to).
            let visible = use_group.map(|g| my_groups.iter().any(|(gid, _)| *gid == g)).unwrap_or(false);
            let in_use_group_name = if visible {
                use_group.and_then(|g| my_groups.iter().find(|(gid, _)| *gid == g).map(|(_, n)| n.clone()))
            } else {
                None
            };
            CredentialView {
                id,
                bintang_name: name,
                bintang_password: pass,
                posted_by,
                posted_by_name,
                posted_at,
                has_screenshot: shot.is_some(),
                in_use: court.is_some(),
                in_use_court: if visible { court } else { None },
                clears_at,
                is_mine,
                shared_group_ids,
                in_use_group_name,
                in_use_elsewhere: court.is_some() && !visible,
            }
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
    /// Groups to share this login with. Defaults to the active group. Every id
    /// must be a group the poster belongs to.
    #[serde(default)]
    pub group_ids: Option<Vec<Uuid>>,
}

/// Filter `requested` down to groups the user actually belongs to; error on any
/// id that isn't theirs (no silently sharing into foreign groups).
async fn validate_share_groups(
    state: &AppState,
    user_id: Uuid,
    requested: &[Uuid],
) -> Result<Vec<Uuid>, ApiError> {
    let mut unique: Vec<Uuid> = Vec::new();
    for g in requested {
        if !unique.contains(g) {
            unique.push(*g);
        }
    }
    if unique.is_empty() {
        return Ok(unique);
    }
    let member_of: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT group_id FROM group_members WHERE user_id = $1 AND group_id = ANY($2)",
    )
    .bind(user_id)
    .bind(&unique)
    .fetch_all(&state.db)
    .await?;
    if member_of.len() != unique.len() {
        return Err(ApiError::Forbidden);
    }
    Ok(unique)
}

pub async fn post_credential(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<PostCredentialReq>,
) -> Result<Json<ApiResponse<CredentialView>>, ApiError> {
    let ctx = active_group(&state, user.id).await?;
    let name = req.bintang_name.trim();
    let pass = req.bintang_password.trim();
    // chars(), not len(): the clients validate 50 characters, not 50 bytes.
    if name.is_empty()
        || name.chars().count() > 50
        || pass.is_empty()
        || pass.chars().count() > 50
    {
        return Err(ApiError::BadRequest("name and password are required (max 50 chars)".into()));
    }
    // Only accept a screenshot path we actually created for today.
    let screenshot = req
        .screenshot_path
        .as_deref()
        .filter(|p| p.starts_with(&creds_dir(&state, time::today())));

    // Default share: the group you're playing with right now.
    let share_groups = match &req.group_ids {
        Some(ids) => validate_share_groups(&state, user.id, ids).await?,
        None => vec![ctx.group_id],
    };

    let mut tx = state.db.begin().await?;
    let id: (Uuid,) = sqlx::query_as(
        "INSERT INTO court_credentials (posted_by, game_date, bintang_name, bintang_password, screenshot_path)
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(user.id)
    .bind(time::today())
    .bind(name)
    .bind(pass)
    .bind(screenshot)
    .fetch_one(&mut *tx)
    .await?;
    for g in &share_groups {
        sqlx::query("INSERT INTO credential_shares (credential_id, group_id) VALUES ($1, $2)")
            .bind(id.0)
            .bind(g)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;

    security::log(&state, event::CREDENTIAL_POSTED, Some(user.id), None, serde_json::json!({})).await;
    state.broadcast(LiveEvent::CredentialsChanged);

    let poster_name: (String,) = sqlx::query_as("SELECT display_name FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&state.db)
        .await?;
    notify::credential_posted(&state, share_groups.clone(), user.id, &poster_name.0);

    let cards = today(State(state.clone()), user, axum::extract::Query(TodayQuery { scope: None })).await?;
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
pub struct OcrLogin {
    pub bintang_name: String,
    pub bintang_password: String,
}

#[derive(Serialize)]
pub struct OcrResult {
    /// Every login read from the image (handwritten notes can hold several).
    pub logins: Vec<OcrLogin>,
    pub ok: bool,
    pub screenshot_path: Option<String>,
    pub message: String,
}

/// Accept a screenshot (multipart field "image"), OCR it, and stash the file.
pub async fn ocr_credential(
    State(state): State<AppState>,
    user: AuthUser,
    multipart: Multipart,
) -> Result<Json<ApiResponse<OcrResult>>, ApiError> {
    let max_bytes = state.config.max_upload_size_mb * 1024 * 1024;
    let (bytes, content_type) = crate::upload::read_image_field(multipart, max_bytes).await?;

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

    let (pairs, ocr_error) = match ocr::extract(&state, &bytes, &content_type).await {
        Some(pairs) => (pairs, false),
        None => (Vec::new(), true), // call failed — degrade to manual entry
    };
    let ok = !pairs.is_empty();
    metrics::record_ocr_scan(
        "login",
        if ocr_error { "error" } else if ok { "matched" } else { "no_match" },
    );
    let message = match pairs.len() {
        0 => "Couldn't read it clearly — please add the login(s) manually.".to_string(),
        1 => "Review the login below and confirm.".to_string(),
        n => format!("Found {n} logins — review and confirm."),
    };
    let logins = pairs
        .into_iter()
        .map(|p| OcrLogin { bintang_name: p.name, bintang_password: p.password })
        .collect();
    let _ = user; // upload attributed implicitly; auth gate is the point.

    Ok(Json(ApiResponse::ok(OcrResult { logins, ok, screenshot_path, message })))
}

/// Stream a credential's screenshot — only to its owner or members viewing it
/// through their ACTIVE group (same visibility rule as the today list).
pub async fn screenshot(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let ctx = active_group(&state, user.id).await?;
    let row: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT c.screenshot_path FROM court_credentials c
         WHERE c.id = $1
           AND (c.posted_by = $2
                OR EXISTS (SELECT 1 FROM credential_shares s
                           WHERE s.credential_id = c.id AND s.group_id = $3))",
    )
    .bind(id)
    .bind(user.id)
    .bind(ctx.group_id)
    .fetch_optional(&state.db)
    .await?;
    let path = row.and_then(|r| r.0).ok_or(ApiError::NotFound)?;
    let bytes = tokio::fs::read(&path).await.map_err(|_| ApiError::NotFound)?;
    let ctype = if path.ends_with(".png") { "image/png" } else { "image/jpeg" };
    Ok(([(header::CONTENT_TYPE, ctype)], bytes).into_response())
}

#[derive(Deserialize)]
pub struct SetSharesReq {
    pub group_ids: Vec<Uuid>,
}

#[derive(Deserialize)]
pub struct UpdateCredentialReq {
    pub bintang_name: String,
    pub bintang_password: String,
}

/// Owner-only: fix a typo in a posted login (name/password). Sharing stays
/// as picked — that's PUT :id/shares.
pub async fn update_credential(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateCredentialReq>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    let name = req.bintang_name.trim();
    let pass = req.bintang_password.trim();
    // chars(), not len(): the clients validate 50 characters, not 50 bytes.
    if name.is_empty()
        || name.chars().count() > 50
        || pass.is_empty()
        || pass.chars().count() > 50
    {
        return Err(ApiError::BadRequest("name and password are required (max 50 chars)".into()));
    }
    let owner: Option<(Uuid,)> =
        sqlx::query_as("SELECT posted_by FROM court_credentials WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
    match owner {
        None => return Err(ApiError::NotFound),
        Some((posted_by,)) if posted_by != user.id => return Err(ApiError::Forbidden),
        Some(_) => {}
    }
    sqlx::query(
        "UPDATE court_credentials SET bintang_name = $1, bintang_password = $2 WHERE id = $3",
    )
    .bind(name)
    .bind(pass)
    .bind(id)
    .execute(&state.db)
    .await?;
    security::log(&state, event::CREDENTIAL_UPDATED, Some(user.id), None, serde_json::json!({ "id": id })).await;
    state.broadcast(LiveEvent::CredentialsChanged);
    Ok(Json(ApiResponse::message("Login updated.")))
}

/// Owner-only: re-point which groups can see this login.
pub async fn set_shares(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<SetSharesReq>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    let owner: Option<(Uuid,)> =
        sqlx::query_as("SELECT posted_by FROM court_credentials WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
    let (owner,) = owner.ok_or(ApiError::NotFound)?;
    if owner != user.id {
        return Err(ApiError::Forbidden);
    }
    let groups = validate_share_groups(&state, user.id, &req.group_ids).await?;

    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM credential_shares WHERE credential_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    for g in &groups {
        sqlx::query("INSERT INTO credential_shares (credential_id, group_id) VALUES ($1, $2)")
            .bind(id)
            .bind(g)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    state.broadcast(LiveEvent::CredentialsChanged);
    Ok(Json(ApiResponse::message("Sharing updated.")))
}

/// Owner: hard-delete their login everywhere. Group admin (non-owner): remove
/// it from THEIR group only — other groups' visibility is not theirs to touch.
pub async fn delete_credential(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    let row: Option<(Uuid, Option<String>)> =
        sqlx::query_as("SELECT posted_by, screenshot_path FROM court_credentials WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
    let (posted_by, path) = row.ok_or(ApiError::NotFound)?;

    if posted_by == user.id {
        sqlx::query("DELETE FROM court_credentials WHERE id = $1")
            .bind(id)
            .execute(&state.db)
            .await?;
        if let Some(p) = path {
            let _ = tokio::fs::remove_file(p).await;
        }
        security::log(&state, event::CREDENTIAL_DELETED, Some(user.id), None, serde_json::json!({ "id": id })).await;
        state.broadcast(LiveEvent::CredentialsChanged);
        return Ok(Json(ApiResponse::message("Login deleted.")));
    }

    // Not the owner → must be an admin of the active group, and the login must
    // be shared there; the action is an unshare, not a delete.
    let ctx = require_group_admin(&state, user.id).await?;
    let res = sqlx::query(
        "DELETE FROM credential_shares WHERE credential_id = $1 AND group_id = $2",
    )
    .bind(id)
    .bind(ctx.group_id)
    .execute(&state.db)
    .await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    security::log(&state, event::CREDENTIAL_DELETED, Some(user.id), None, serde_json::json!({ "id": id, "unshared_from": ctx.group_id })).await;
    state.broadcast(LiveEvent::CredentialsChanged);
    Ok(Json(ApiResponse::message("Login removed from this group.")))
}

/// Group admin: remove ALL of today's logins from this group's view (their
/// owners keep them; other groups are untouched).
pub async fn clear_today(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let ctx = require_group_admin(&state, user.id).await?;
    let res = sqlx::query(
        "DELETE FROM credential_shares s
         USING court_credentials c
         WHERE s.credential_id = c.id AND s.group_id = $1 AND c.game_date = $2",
    )
    .bind(ctx.group_id)
    .bind(time::today())
    .execute(&state.db)
    .await?;
    let removed = res.rows_affected();
    security::log(&state, event::ADMIN_ACTION, Some(user.id), None, serde_json::json!({ "action": "clear_credentials", "removed": removed })).await;
    state.broadcast(LiveEvent::CredentialsChanged);
    Ok(Json(ApiResponse::ok(serde_json::json!({ "removed": removed }))))
}

/// Directory for a given game date's screenshots, relative to UPLOADS_PATH.
fn creds_dir(state: &AppState, date: chrono::NaiveDate) -> String {
    format!("{}/creds/{}", state.config.uploads_path.trim_end_matches('/'), date)
}
