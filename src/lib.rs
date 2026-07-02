pub mod auth;
pub mod config;
pub mod downstream;
pub mod email;
pub mod error;
pub mod jobs;
pub mod metrics;
pub mod models;
pub mod net;
pub mod notify;
pub mod ocr;
pub mod otp;
pub mod push;
pub mod routes;
pub mod security;
pub mod state;
pub mod time;
pub mod upload;

use std::net::SocketAddr;
use std::time::Duration;

use axum::extract::{ConnectInfo, DefaultBodyLimit, MatchedPath, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::Router;
use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

use error::ApiError;
use net::client_ip;
use state::AppState;

pub fn build_app(state: AppState, static_dir: Option<String>) -> Router {
    metrics::register_metrics();
    let cors = build_cors(&state.config.allowed_origins);
    // Headroom above the per-upload cap so the handler's own size check trips
    // first and can drain the body cleanly (see upload::read_image_field).
    let body_limit = (state.config.max_upload_size_mb + 10) * 1024 * 1024;

    let mut app = Router::new()
        .route("/health", get(routes::health::health_check))
        .route("/metrics", get(metrics_endpoint))
        // ---- auth ----------------------------------------------------------
        .route("/api/auth/signup", post(routes::auth::signup))
        .route("/api/auth/signup/verify", post(routes::auth::signup_verify))
        .route("/api/auth/login", post(routes::auth::login))
        .route("/api/auth/login/verify", post(routes::auth::login_verify))
        .route("/api/auth/logout", post(routes::auth::logout))
        .route("/api/auth/me", get(routes::auth::me).patch(routes::auth::update_me))
        // ---- groups ----------------------------------------------------------
        .route("/api/groups", get(routes::groups::list_mine).post(routes::groups::create_group))
        .route("/api/groups/active", put(routes::groups::set_active))
        .route(
            "/api/groups/current",
            get(routes::groups::current_group).put(routes::groups::rename_group),
        )
        .route("/api/groups/leave", post(routes::groups::leave_group))
        .route(
            "/api/groups/members/:id",
            put(routes::groups::set_member_role).delete(routes::groups::remove_member),
        )
        .route(
            "/api/groups/invites",
            get(routes::groups::list_group_invites).post(routes::groups::send_invite),
        )
        .route("/api/groups/invites/:id", delete(routes::groups::revoke_invite))
        .route("/api/invites", get(routes::groups::my_invites))
        .route("/api/invites/:id/accept", post(routes::groups::accept_invite))
        .route("/api/invites/:id/decline", post(routes::groups::decline_invite))
        // ---- polls ---------------------------------------------------------
        .route("/api/polls/today", get(routes::polls::today))
        .route("/api/polls/history", get(routes::polls::history))
        .route("/api/polls", post(routes::polls::create_poll))
        .route("/api/polls/:id", get(routes::polls::get_poll).delete(routes::polls::delete_poll))
        .route("/api/polls/:id/vote", put(routes::polls::vote).delete(routes::polls::retract_vote))
        .route("/api/polls/:id/attendance", post(routes::polls::confirm_attendance))
        .route("/api/members", get(routes::polls::members))
        // ---- credentials ---------------------------------------------------
        .route("/api/credentials/today", get(routes::credentials::today))
        .route("/api/credentials", post(routes::credentials::post_credential))
        .route("/api/credentials/ocr", post(routes::credentials::ocr_credential))
        .route("/api/credentials/clear-today", post(routes::credentials::clear_today))
        .route("/api/credentials/:id", delete(routes::credentials::delete_credential))
        .route("/api/credentials/:id/shares", put(routes::credentials::set_shares))
        .route("/api/credentials/:id/screenshot", get(routes::credentials::screenshot))
        // ---- reservations --------------------------------------------------
        .route("/api/reservations/today", get(routes::reservations::today))
        .route("/api/reservations/stream", get(routes::stream::reservations_stream))
        .route("/api/reservations/scan-board", post(routes::reservations::scan_board))
        .route("/api/reservations", post(routes::reservations::create))
        .route("/api/reservations/credentials/:id/unlock", put(routes::reservations::unlock_credential))
        .route("/api/reservations/:id", put(routes::reservations::edit))
        .route("/api/reservations/:id/complete", put(routes::reservations::complete))
        .route("/api/reservations/:id/cancel", put(routes::reservations::cancel))
        // ---- kcal ----------------------------------------------------------
        .route("/api/kcal/today", get(routes::kcal::today))
        .route("/api/kcal/history", get(routes::kcal::history))
        .route("/api/kcal", post(routes::kcal::log))
        // ---- push ----------------------------------------------------------
        .route("/api/push/vapid-public-key", get(routes::push::vapid_public_key))
        .route(
            "/api/push/subscribe",
            post(routes::push::subscribe).delete(routes::push::unsubscribe),
        )
        // ---- config --------------------------------------------------------
        .route(
            "/api/config/auto-poll",
            get(routes::config::get_auto_poll).put(routes::config::set_auto_poll),
        )
        // ---- admin ---------------------------------------------------------
        .route("/api/admin/members", get(routes::admin::list_members))
        .route("/api/admin/members/:id", get(routes::admin::member_detail))
        .route("/api/admin/members/:id/approve", post(routes::admin::approve_member))
        .route("/api/admin/members/:id/reject", post(routes::admin::reject_member))
        .route("/api/admin/members/:id/deactivate", post(routes::admin::deactivate_member))
        .route("/api/admin/members/:id/reactivate", post(routes::admin::reactivate_member))
        .route("/api/admin/members/:id/clear-lock", post(routes::admin::clear_lock))
        .route("/api/admin/invites", get(routes::admin::list_invites).post(routes::admin::generate_invites))
        .route("/api/admin/invites/:id/revoke", post(routes::admin::revoke_invite))
        .route("/api/admin/security", get(routes::admin::security_log))
        .route("/api/admin/health", get(routes::admin::system_health))
        // ---- middleware ----------------------------------------------------
        // route_layer so MatchedPath is populated when track_metrics runs
        // (gives bounded-cardinality endpoint labels, not raw paths).
        .route_layer(middleware::from_fn(track_metrics))
        .layer(middleware::from_fn(server_time_header))
        .layer(middleware::from_fn_with_state(state.clone(), api_rate_limit))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(DefaultBodyLimit::max(body_limit))
        .with_state(state);

    if let Some(dir) = static_dir {
        if std::path::Path::new(&dir).is_dir() {
            let index = std::path::Path::new(&dir).join("index.html");
            app = app.fallback_service(ServeDir::new(&dir).fallback(ServeFile::new(index)));
            tracing::info!(dir, "serving frontend");
        } else {
            tracing::warn!(dir, "STATIC_DIR does not exist — frontend not served");
        }
    }

    app.layer(middleware::from_fn(security_headers))
}

/// Record per-request metrics using the matched route template as the endpoint
/// label (bounded cardinality), not the raw path.
async fn track_metrics(req: Request, next: Next) -> Response {
    let method = req.method().as_str().to_owned();
    let endpoint = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".to_owned());
    let start = std::time::Instant::now();
    let resp = next.run(req).await;
    let elapsed = start.elapsed().as_secs_f64();
    metrics::record_request(&method, &endpoint, resp.status().as_u16(), elapsed);
    resp
}

/// Token-gated `/metrics`. When METRICS_TOKEN is set, require it and answer 404
/// (not 401) on mismatch so the endpoint stays invisible.
async fn metrics_endpoint(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(expected) = &state.config.metrics_token {
        let authorized = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|t| t == expected)
            .unwrap_or(false);
        if !authorized {
            return StatusCode::NOT_FOUND.into_response();
        }
    }
    metrics::metrics_handler().into_response()
}

fn request_ip(req: &Request) -> std::net::IpAddr {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0)
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    client_ip(req.headers(), peer)
}

async fn api_rate_limit(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if !state.rate_api.check(request_ip(&req)) {
        return Err(ApiError::TooManyRequests);
    }
    Ok(next.run(req).await)
}

/// Expose server time so clients can correct clock drift in timers (PRD §7.2.2).
async fn server_time_header(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    if let Ok(v) = HeaderValue::from_str(&crate::time::now().to_rfc3339()) {
        resp.headers_mut().insert("x-server-time", v);
    }
    resp
}

async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    let set = |h: &mut axum::http::HeaderMap, k: &'static str, v: &'static str| {
        h.insert(k, HeaderValue::from_static(v));
    };
    set(h, "x-content-type-options", "nosniff");
    set(h, "x-frame-options", "DENY");
    set(h, "referrer-policy", "no-referrer");
    set(h, "permissions-policy", "microphone=(), geolocation=()");
    resp
}

pub fn build_cors(allowed_origins: &[String]) -> CorsLayer {
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::PATCH, Method::DELETE])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .allow_credentials(true);

    let origins: Vec<HeaderValue> = allowed_origins
        .iter()
        .filter_map(|o| o.parse().ok())
        .collect();

    if origins.is_empty() {
        tracing::info!("CORS: same-origin only");
        cors
    } else {
        tracing::info!(?allowed_origins, "CORS: cross-origin allowed for listed origins");
        cors.allow_origin(origins)
    }
}

pub async fn connect_redis(redis_url: &str) -> Option<ConnectionManager> {
    let client = match redis::Client::open(redis_url) {
        Ok(client) => client,
        Err(e) => {
            tracing::warn!(error = %e, "invalid REDIS_URL — running without rate limiting/OTP store");
            return None;
        }
    };
    let manager_config = ConnectionManagerConfig::new()
        .set_number_of_retries(2)
        .set_max_delay(500)
        .set_connection_timeout(Duration::from_secs(2))
        .set_response_timeout(Duration::from_secs(2));
    match ConnectionManager::new_with_config(client, manager_config).await {
        Ok(conn) => {
            tracing::info!("connected to Redis");
            Some(conn)
        }
        Err(e) => {
            tracing::warn!(error = %e, "Redis unreachable — OTP/rate-limit features degraded");
            None
        }
    }
}

pub async fn run_migrations(db: &PgPool, database_url: &str) {
    let first_try = sqlx::migrate!().run(db).await;
    let err = match first_try {
        Ok(()) => {
            tracing::info!("database migrations applied");
            return;
        }
        Err(e) => e,
    };
    let missing_db = err.to_string().contains("does not exist") || err.to_string().contains("3D000");
    if missing_db && create_database(database_url).await {
        match sqlx::migrate!().run(db).await {
            Ok(()) => {
                tracing::info!("database created and migrations applied");
                return;
            }
            Err(e) => tracing::warn!(error = %e, "migrations failed after creating database"),
        }
    }
    tracing::warn!(error = %err, "Postgres unreachable — endpoints will fail until it is up");
}

async fn create_database(database_url: &str) -> bool {
    let Ok(mut url) = url::Url::parse(database_url) else { return false };
    let db_name = url.path().trim_start_matches('/').to_string();
    if db_name.is_empty() || db_name.contains('"') {
        return false;
    }
    url.set_path("/postgres");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(3))
        .connect(url.as_str())
        .await;
    let Ok(admin) = admin else { return false };
    tracing::info!(db = db_name, "database missing — creating it");
    sqlx::query(&format!(r#"CREATE DATABASE "{db_name}""#))
        .execute(&admin)
        .await
        .is_ok()
}

/// Promote the configured owner email to admin (idempotent).
pub async fn promote_admin(db: &PgPool, admin_email: &str) {
    if let Ok(r) = sqlx::query("UPDATE users SET role = 'admin' WHERE LOWER(email) = $1 AND role <> 'admin'")
        .bind(admin_email.to_lowercase())
        .execute(db)
        .await
    {
        if r.rows_affected() > 0 {
            tracing::info!(email = admin_email, "promoted owner to admin");
        }
    }
}

/// Map a tower StatusCode 404 into our envelope for unknown API routes.
#[allow(dead_code)]
async fn not_found() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "not found")
}
