use axum::{
    extract::{Query, State, Json as ExtractJson},
    http::HeaderMap,
    response::Json,
};
use serde::{Deserialize, Serialize};
use validator::Validate;
use uuid::Uuid;
use utoipa::ToSchema;

use crate::{
    errors::AppError,
    AppState,
};

// Request and Response structures
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct RegisterRequest {
    /// User email address
    #[validate(email)]
    #[schema(example = "user@example.com")]
    pub email: String,
    /// Password (minimum 8 characters)
    #[validate(length(min = 8))]
    #[schema(example = "securepassword123")]
    pub password: String,
    /// User first name (minimum 2 characters)
    #[validate(length(min = 2))]
    #[schema(example = "John")]
    pub first_name: String,
    /// User last name (minimum 2 characters)
    #[validate(length(min = 2))]
    #[schema(example = "Doe")]
    pub last_name: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RegisterResponse {
    /// Success message
    #[schema(example = "User registered successfully")]
    pub message: String,
    /// The ID of the newly created user
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub user_id: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct LoginRequest {
    /// User email address
    #[validate(email)]
    #[schema(example = "user@example.com")]
    pub email: String,
    /// User password
    #[validate(length(min = 1))]
    #[schema(example = "securepassword123")]
    pub password: String,
    /// Optional device name for session tracking
    #[schema(example = "iPhone 12")]
    pub device_name: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LoginResponse {
    /// JWT access token
    #[schema(example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")]
    pub access_token: String,
    /// JWT refresh token
    #[schema(example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")]
    pub refresh_token: String,
    /// Access token expiration time in seconds
    #[schema(example = 900)]
    pub access_expires_in: i64,
    /// Refresh token expiration time in seconds
    #[schema(example = 604800)]
    pub refresh_expires_in: i64,
    /// Token type
    #[schema(example = "Bearer")]
    pub token_type: String,
    /// User information
    pub user: UserInfo,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct RefreshTokenRequest {
    /// JWT refresh token
    #[validate(length(min = 10))]
    #[schema(example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")]
    pub refresh_token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RefreshResponse {
    /// New JWT access token
    #[schema(example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")]
    pub access_token: String,
    /// New JWT refresh token
    #[schema(example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")]
    pub refresh_token: String,
    /// Access token expiration time in seconds
    #[schema(example = 900)]
    pub access_expires_in: i64,
    /// Refresh token expiration time in seconds
    #[schema(example = 604800)]
    pub refresh_expires_in: i64,
    /// Token type
    #[schema(example = "Bearer")]
    pub token_type: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyEmailQuery {
    /// Email verification code
    #[schema(example = "ABC123DEF456")]
    pub code: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ForgotPasswordRequest {
    /// User email address
    #[validate(email)]
    #[schema(example = "user@example.com")]
    pub email: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ResetPasswordRequest {
    /// Password reset code
    #[validate(length(min = 1))]
    #[schema(example = "RST123ABC456")]
    pub code: String,
    /// New password (minimum 8 characters)
    #[validate(length(min = 8))]
    #[schema(example = "newsecurepassword123")]
    pub new_password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MessageResponse {
    /// Response message
    #[schema(example = "Operation completed successfully")]
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserInfo {
    /// User ID
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub id: String,
    /// User email address
    #[schema(example = "user@example.com")]
    pub email: String,
    /// User first name
    #[schema(example = "John")]
    pub first_name: String,
    /// User last name
    #[schema(example = "Doe")]
    pub last_name: String,
    /// Email verification status
    #[schema(example = true)]
    pub email_verified: bool,
    /// Account creation timestamp
    #[schema(example = "2023-01-01T00:00:00Z")]
    pub created_at: chrono::DateTime<chrono::Utc>,
}

// Helper function to extract device fingerprint
fn extract_device_fingerprint(headers: &HeaderMap) -> String {
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    
    let accept_language = headers
        .get("accept-language")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("en")
        .to_string();
    
    format!("{}-{}", user_agent, accept_language)
}

// Simplified Authentication handlers for now
/// Register a new user account
#[utoipa::path(
    post,
    path = "/auth/register",
    tags = ["auth"],
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "User registered successfully", body = RegisterResponse),
        (status = 400, description = "Validation error", body = AppError),
        (status = 409, description = "User already exists", body = AppError),
        (status = 500, description = "Internal server error", body = AppError)
    )
)]
pub async fn register_handler(
    State(state): State<AppState>,
    ExtractJson(request): ExtractJson<RegisterRequest>,
) -> Result<Json<RegisterResponse>, AppError> {
    // Validate input
    request.validate()?;
    
    // Simplified implementation - just hash password and return success
    let user_id = uuid::Uuid::new_v4();
    let _password_hash = state.password_service.hash_password(&request.password)?;

    tracing::info!("User registered: {}", user_id);

    let response = RegisterResponse {
        message: "User registered successfully. Please check your email for verification.".to_string(),
        user_id: user_id.to_string(),
    };

    Ok(Json(response))
}

/// Authenticate user and return JWT tokens
#[utoipa::path(
    post,
    path = "/auth/login",
    tags = ["auth"],
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = LoginResponse),
        (status = 400, description = "Validation error", body = AppError),
        (status = 401, description = "Invalid credentials", body = AppError),
        (status = 500, description = "Internal server error", body = AppError)
    )
)]
pub async fn login_handler(
    State(state): State<AppState>,
    _headers: HeaderMap,
    ExtractJson(request): ExtractJson<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    // Validate input
    request.validate()?;

    // Simplified implementation for now
    let user_id = uuid::Uuid::new_v4();
    let device_id = uuid::Uuid::new_v4();

    // Generate JWT token pair
    let token_pair = state.jwt_service.generate_token_pair(
        &user_id.to_string(),
        &request.email,
        &device_id.to_string(),
    )?;

    tracing::info!("User logged in: {}", user_id);

    let user_info = UserInfo {
        id: user_id.to_string(),
        email: request.email.clone(),
        first_name: "Test".to_string(),
        last_name: "User".to_string(),
        email_verified: true,
        created_at: chrono::Utc::now(),
    };

    let response = LoginResponse {
        access_token: token_pair.access_token,
        refresh_token: token_pair.refresh_token,
        access_expires_in: token_pair.access_expires_in,
        refresh_expires_in: token_pair.refresh_expires_in,
        token_type: token_pair.token_type,
        user: user_info,
    };

    Ok(Json(response))
}

pub async fn logout_handler(
    State(_state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<MessageResponse>, AppError> {
    // Extract authorization header for validation
    let auth_header = headers
        .get("authorization")
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| AppError::Authentication("Missing authorization header".to_string()))?;

    // Basic validation that it starts with "Bearer "
    if !auth_header.starts_with("Bearer ") {
        return Err(AppError::Authentication("Invalid authorization format".to_string()));
    }

    tracing::info!("User logged out");

    Ok(Json(MessageResponse {
        message: "Logged out successfully".to_string(),
    }))
}

pub async fn refresh_handler(
    State(state): State<AppState>,
    ExtractJson(request): ExtractJson<RefreshTokenRequest>,
) -> Result<Json<RefreshResponse>, AppError> {
    // Validate refresh token
    let refresh_claims = state.jwt_service.validate_refresh_token(&request.refresh_token)?;
    let user_id = Uuid::parse_str(&refresh_claims.sub)?;
    let device_id = &refresh_claims.device_id;

    // Generate new token pair
    let new_token_pair = state.jwt_service.generate_token_pair(
        &user_id.to_string(),
        "test@example.com",
        &device_id,
    )?;

    let response = RefreshResponse {
        access_token: new_token_pair.access_token,
        refresh_token: new_token_pair.refresh_token,
        access_expires_in: new_token_pair.access_expires_in,
        refresh_expires_in: new_token_pair.refresh_expires_in,
        token_type: new_token_pair.token_type,
    };

    Ok(Json(response))
}

pub async fn verify_email_handler(
    State(_state): State<AppState>,
    Query(params): Query<VerifyEmailQuery>,
) -> Result<Json<MessageResponse>, AppError> {
    // Simplified implementation for now
    tracing::info!("Email verification attempted for code: {}", params.code);

    Ok(Json(MessageResponse {
        message: "Email verified successfully".to_string(),
    }))
}

pub async fn forgot_password_handler(
    State(_state): State<AppState>,
    ExtractJson(request): ExtractJson<ForgotPasswordRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    // Validate input
    request.validate()?;

    // Simplified implementation for now
    tracing::info!("Password reset requested for email: {}", request.email);

    // Always return success to prevent email enumeration
    Ok(Json(MessageResponse {
        message: "If the email exists, a password reset link has been sent".to_string(),
    }))
}

pub async fn reset_password_handler(
    State(state): State<AppState>,
    ExtractJson(request): ExtractJson<ResetPasswordRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    // Validate input
    request.validate()?;

    // Simplified implementation for now - just validate password format
    let _password_hash = state.password_service.hash_password(&request.new_password)?;
    
    tracing::info!("Password reset completed for code: {}", request.code);

    Ok(Json(MessageResponse {
        message: "Password reset successfully".to_string(),
    }))
}