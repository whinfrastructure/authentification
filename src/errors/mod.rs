use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;
use validator::ValidationErrors;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),
    
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    
    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Validation errors")]
    ValidationErrors(#[from] ValidationErrors),

    #[error("UUID parsing error: {0}")]
    UuidError(#[from] uuid::Error),
    
    #[error("Authentication error: {0}")]
    Authentication(String),
    
    #[error("Authorization error: {0}")]
    Authorization(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Rate limit exceeded")]
    RateLimit,
    
    #[error("Email error: {0}")]
    Email(#[from] lettre::error::Error),
    
    #[error("SMTP error: {0}")]
    Smtp(#[from] lettre::transport::smtp::Error),
    
    #[error("Address error: {0}")]
    Address(#[from] lettre::address::AddressError),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Internal server error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            AppError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
            AppError::Redis(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Cache error"),
            AppError::Jwt(_) => (StatusCode::UNAUTHORIZED, "Invalid token"),
            AppError::Validation(msg) => (StatusCode::BAD_REQUEST, msg.as_str()),
            AppError::Authentication(msg) => (StatusCode::UNAUTHORIZED, msg.as_str()),
            AppError::Authorization(msg) => (StatusCode::FORBIDDEN, msg.as_str()),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.as_str()),
            AppError::RateLimit => (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded"),
            AppError::Email(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Email service error"),
            AppError::Smtp(_) => (StatusCode::INTERNAL_SERVER_ERROR, "SMTP service error"),
            AppError::Address(_) => (StatusCode::BAD_REQUEST, "Invalid email address"),
            AppError::Config(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.as_str()),
            AppError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.as_str()),
            AppError::ValidationErrors(_) => (StatusCode::BAD_REQUEST, "Validation failed"),
            AppError::UuidError(_) => (StatusCode::BAD_REQUEST, "Invalid UUID format"),
        };

        let body = Json(json!({
            "error": error_message,
            "message": self.to_string(),
        }));

        (status, body).into_response()
    }
}

pub type Result<T> = std::result::Result<T, AppError>;