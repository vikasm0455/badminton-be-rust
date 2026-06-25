use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub redis_url: String,
    pub jwt_secret: String,
    /// Resend.com API key. When unset, OTP codes are logged to the console
    /// (dev mode) instead of being emailed.
    pub resend_api_key: Option<String>,
    /// From address for outgoing mail, e.g. "RallyUp <badminton@boyishesh.com>".
    pub email_from: String,
    /// Anthropic API key for Claude Vision OCR. When unset, the OCR endpoint
    /// returns empty fields so the user falls back to manual entry.
    pub anthropic_api_key: Option<String>,
    /// Claude model used for screenshot OCR.
    pub anthropic_model: String,
    /// The owner's email — always treated as admin (PRD §3, single admin v1).
    pub admin_email: Option<String>,
    /// VAPID contact subject, e.g. "mailto:admin@boyishesh.com".
    pub vapid_subject: String,
    /// Where credential screenshots are written (cleared nightly).
    pub uploads_path: String,
    /// Max credential screenshot upload size (MB).
    pub max_upload_size_mb: usize,
    /// Set Secure flag on the auth cookie (on behind HTTPS / Cloudflare).
    pub cookie_secure: bool,
    /// Browser origins allowed to call the API cross-origin (dev). Empty in
    /// prod where the frontend is same-origin behind Nginx.
    pub allowed_origins: Vec<String>,
    /// When set, `/metrics` requires `Authorization: Bearer <token>` (404 otherwise).
    pub metrics_token: Option<String>,
    pub port: u16,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://postgres:postgres@127.0.0.1:5432/rallyup".to_string()
        });
        let redis_url =
            env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

        let jwt_secret = match env::var("JWT_SECRET") {
            Ok(secret) if secret.len() >= 32 => secret,
            Ok(_) => {
                return Err("JWT_SECRET must be at least 32 characters — generate one with: \
                            openssl rand -base64 48"
                    .to_string());
            }
            Err(_) => {
                tracing::warn!(
                    "JWT_SECRET is not set — using a random secret, all logins reset on restart"
                );
                format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4())
            }
        };

        let resend_api_key = env::var("RESEND_API_KEY").ok().filter(|k| !k.is_empty());
        let email_from = env::var("FROM_EMAIL")
            .or_else(|_| env::var("EMAIL_FROM"))
            .ok()
            .filter(|f| !f.is_empty())
            .unwrap_or_else(|| "RallyUp <onboarding@resend.dev>".to_string());

        let anthropic_api_key = env::var("ANTHROPIC_API_KEY").ok().filter(|k| !k.is_empty());
        let anthropic_model = env::var("ANTHROPIC_MODEL")
            .ok()
            .filter(|m| !m.is_empty())
            .unwrap_or_else(|| "claude-sonnet-4-6".to_string());

        let admin_email = env::var("ADMIN_EMAIL")
            .ok()
            .map(|e| e.trim().to_lowercase())
            .filter(|e| !e.is_empty());

        let vapid_subject = env::var("VAPID_SUBJECT")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "mailto:admin@example.com".to_string());

        let uploads_path =
            env::var("UPLOADS_PATH").unwrap_or_else(|_| "./uploads".to_string());
        let max_upload_size_mb = env::var("MAX_UPLOAD_SIZE_MB")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(15);

        let cookie_secure = env::var("COOKIE_SECURE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let allowed_origins = match env::var("ALLOWED_ORIGINS") {
            Ok(raw) => raw
                .split(',')
                .map(|o| o.trim().to_string())
                .filter(|o| !o.is_empty())
                .collect(),
            Err(_) => vec![
                "http://localhost:3090".to_string(),
                "http://127.0.0.1:3090".to_string(),
            ],
        };

        let metrics_token = env::var("METRICS_TOKEN").ok().filter(|t| !t.is_empty());

        let port = env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8090);

        Ok(Self {
            database_url,
            redis_url,
            jwt_secret,
            resend_api_key,
            email_from,
            anthropic_api_key,
            anthropic_model,
            admin_email,
            vapid_subject,
            uploads_path,
            max_upload_size_mb,
            cookie_secure,
            allowed_origins,
            metrics_token,
            port,
        })
    }
}
