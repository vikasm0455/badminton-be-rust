use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use tokio::sync::broadcast;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use rallyup_api::config::Config;
use rallyup_api::net::RateLimiter;
use rallyup_api::push::Vapid;
use rallyup_api::state::AppState;
use rallyup_api::{build_app, connect_redis, jobs, promote_admin, run_migrations};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env().add_directive("rallyup_api=debug".parse().unwrap()))
        .init();

    let config = match Config::from_env() {
        Ok(config) => Arc::new(config),
        Err(e) => {
            eprintln!("configuration error: {e}");
            std::process::exit(1);
        }
    };

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("failed to build HTTP client");

    let redis = connect_redis(&config.redis_url).await;

    // Lazy pool: boots before Postgres is up; migrations are best-effort.
    let db = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(3))
        .connect_lazy(&config.database_url)
        .expect("invalid DATABASE_URL");
    run_migrations(&db, &config.database_url).await;

    if let Some(admin_email) = &config.admin_email {
        promote_admin(&db, admin_email).await;
    }

    let vapid = Arc::new(Vapid::load_or_create(&db, &config.vapid_subject).await);
    let (events, _) = broadcast::channel(256);

    let port = config.port;
    let state = AppState {
        config,
        http,
        redis,
        db,
        vapid,
        events,
        rate_api: Arc::new(RateLimiter::new(100, Duration::from_secs(60))),
    };

    // Background scheduler (auto-poll, cleanups, timer notifications).
    jobs::spawn(state.clone());

    let static_dir = std::env::var("STATIC_DIR").ok().filter(|d| !d.is_empty());
    let app = build_app(state, static_dir);

    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tracing::info!("RallyUp API listening on {addr}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
