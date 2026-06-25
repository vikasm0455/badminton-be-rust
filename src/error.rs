use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("too many requests — please slow down")]
    TooManyRequests,
    /// Carries a human message and a retry hint (seconds) for rate-limit walls.
    #[error("{0}")]
    RateLimited(String),
    #[error("could not send the email — please try again")]
    EmailDelivery,
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    PayloadTooLarge(String),
    #[error("database error")]
    Db(#[from] sqlx::Error),
    #[error("internal error")]
    Internal(String),
    /// Upstream service (Anthropic / push provider) failed. Logged, never leaked.
    #[error("service temporarily unavailable")]
    Upstream(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden => StatusCode::FORBIDDEN,
            ApiError::TooManyRequests | ApiError::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,
            ApiError::EmailDelivery => StatusCode::BAD_GATEWAY,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            ApiError::Db(e) => {
                tracing::error!(error = %e, "database query failed");
                StatusCode::INTERNAL_SERVER_ERROR
            }
            ApiError::Internal(msg) => {
                tracing::error!(error = %msg, "internal error");
                StatusCode::INTERNAL_SERVER_ERROR
            }
            ApiError::Upstream(msg) => {
                tracing::error!(error = %msg, "upstream service failed");
                StatusCode::BAD_GATEWAY
            }
        };

        let body = json!({
            "success": false,
            "data": null,
            "message": self.to_string(),
        });
        (status, Json(body)).into_response()
    }
}

impl From<reqwest::Error> for ApiError {
    fn from(e: reqwest::Error) -> Self {
        ApiError::Upstream(e.to_string())
    }
}
