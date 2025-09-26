use axum::{
    extract::{State, Json as ExtractJson},
    http::{StatusCode, HeaderMap},
    response::Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;
use validator::Validate;
use crate::{
    AppState,
    models::{User, DeviceSession, VerificationCode},
    services::{jwt::TokenPair, email::EmailService},
    errors::{AppError, Result},
};

// Request/Response structures for authentication endpoints

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
    pub device_name: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]  
pub struct LoginRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    pub password: String,
    pub device_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct VerifyEmailRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(min = 6, max = 6, message = "Verification code must be 6 digits"))]
    pub code: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ForgotPasswordRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ResetPasswordRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(min = 6, max = 6, message = "Reset code must be 6 digits"))]
    pub code: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub new_password: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub message: String,
    pub user_id: Uuid,
    pub requires_verification: bool,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub message: String,
    pub user_id: Uuid,
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_in: i64,
    pub refresh_expires_in: i64,
    pub token_type: String,
}

#[derive(Debug, Serialize)]
pub struct LogoutResponse {
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct RefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_in: i64,
    pub refresh_expires_in: i64,
    pub token_type: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyEmailResponse {
    pub message: String,
    pub verified: bool,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

// Helper functions

/// Extract device fingerprint from request headers
fn extract_device_fingerprint(headers: &HeaderMap) -> String {
    // Try to get device fingerprint from User-Agent and other headers
    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");
    
    let x_forwarded_for = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    
    let x_real_ip = headers
        .get("x-real-ip")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    
    // Create a basic fingerprint - in production, you'd want more sophisticated fingerprinting
    format!("{}:{}:{}", user_agent, x_forwarded_for, x_real_ip)
}

// Authentication handlers implementation

pub async fn register_handler(
    State(state): State<AppState>,
    ExtractJson(request): ExtractJson<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), AppError> {
    // Validate input
    request.validate()?;

    // Check if user already exists
    if User::find_by_email(&state.database.pool, &request.email).await.is_ok() {
        return Err(AppError::Validation("User with this email already exists".to_string()));
    }

    // Hash password
    let password_service = &state.database.password_service;
    let hashed_password = password_service.hash_password(&request.password)?;

    // Create user
    let user = User::new(
        request.email.clone(),
        hashed_password,
    );

    // Insert user into database
    user.create(&state.database.pool).await?;

    // Generate verification code
    let verification_code = EmailService::generate_verification_code();
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);
    
    let verification = VerificationCode::new(
        user.id,
        verification_code.clone(),
        "email_verification".to_string(),
        expires_at,
    );

    // Store verification code
    verification.create(&state.database.pool).await?;

    // Send verification email
    state.email_service.send_verification_email(&user.email, &verification_code).await?;

    let response = RegisterResponse {
        message: "User registered successfully. Please check your email for verification code.".to_string(),
        user_id: user.id,
        requires_verification: true,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

pub async fn login_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    ExtractJson(request): ExtractJson<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    // Validate input
    request.validate()?;

    // Find user by email
    let user = User::find_by_email(&state.database.pool, &request.email).await
        .map_err(|_| AppError::Authentication("Invalid email or password".to_string()))?;

    // Verify password
    let password_service = &state.database.password_service;
    if !user.verify_password(password_service, &request.password)? {
        return Err(AppError::Authentication("Invalid email or password".to_string()));
    }

    // Check if user is verified (optional, depending on your requirements)
    if !user.email_verified {
        return Err(AppError::Authentication("Please verify your email before logging in".to_string()));
    }

    // Extract device fingerprint
    let device_fingerprint = extract_device_fingerprint(&headers);
    
    // Generate JWT tokens
    let token_pair = state.jwt_service.generate_token_pair(
        &user.id.to_string(),
        &user.email,
        &device_fingerprint,
    )?;

    // Create device session
    let device_session = DeviceSession::new(
        user.id,
        device_fingerprint,
        request.device_name.unwrap_or_else(|| "Unknown Device".to_string()),
        chrono::Utc::now() + chrono::Duration::seconds(token_pair.refresh_expires_in),
    );

    // Store device session
    device_session.create(&state.database.pool).await?;

    let response = LoginResponse {
        message: "Login successful".to_string(),
        user_id: user.id,
        access_token: token_pair.access_token,
        refresh_token: token_pair.refresh_token,
        access_expires_in: token_pair.access_expires_in,
        refresh_expires_in: token_pair.refresh_expires_in,
        token_type: token_pair.token_type,
    };

    Ok(Json(response))
}

pub async fn logout_handler(
    State(state): State<AppState>,
    ExtractJson(request): ExtractJson<LogoutRequest>,
) -> Result<Json<LogoutResponse>, AppError> {
    // Validate refresh token
    let refresh_claims = state.jwt_service.validate_refresh_token(&request.refresh_token)?;

    // Find and invalidate the device session
    if let Ok(mut device_session) = DeviceSession::find_by_user_and_device(
        &state.database.pool,
        &Uuid::parse_str(&refresh_claims.sub)?,
        &refresh_claims.device_id,
    ).await {
        // Mark session as expired
        device_session.expires_at = chrono::Utc::now();
        device_session.update(&state.database.pool).await?;
    }

    let response = LogoutResponse {
        message: "Logged out successfully".to_string(),
    };

    Ok(Json(response))
}

pub async fn refresh_handler(
    State(state): State<AppState>,
    ExtractJson(request): ExtractJson<RefreshTokenRequest>,
) -> Result<Json<RefreshResponse>, AppError> {
    // Validate refresh token
    let refresh_claims = state.jwt_service.validate_refresh_token(&request.refresh_token)?;
    let user_id = Uuid::parse_str(&refresh_claims.sub)?;

    // Check if device session is still valid
    let device_session = DeviceSession::find_by_user_and_device(
        &state.database.pool,
        &user_id,
        &refresh_claims.device_id,
    ).await?;

    if device_session.expires_at <= chrono::Utc::now() {
        return Err(AppError::Authentication("Refresh token expired".to_string()));
    }

    // Get user for new token generation
    let user = User::find_by_id(&state.database.pool, &user_id).await?;

    // Generate new token pair
    let new_token_pair = state.jwt_service.generate_token_pair(
        &user.id.to_string(),
        &user.email,
        &refresh_claims.device_id,
    )?;

    // Update device session with new expiration
    let mut updated_session = device_session;
    updated_session.expires_at = chrono::Utc::now() + chrono::Duration::seconds(new_token_pair.refresh_expires_in);
    updated_session.update(&state.database.pool).await?;

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
) -> Result<Json<serde_json::Value>, StatusCode> {
    Ok(Json(json!({
        "message": "Verify email endpoint - to be implemented",
        "status": "placeholder"
    })))
}

pub async fn forgot_password_handler(
    State(_state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    Ok(Json(json!({
        "message": "Forgot password endpoint - to be implemented",
        "status": "placeholder"
    })))
}

pub async fn reset_password_handler(
    State(_state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    Ok(Json(json!({
        "message": "Reset password endpoint - to be implemented",
        "status": "placeholder"
    })))
}