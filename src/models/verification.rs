use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use uuid::Uuid;
use rand::Rng;
use utoipa::ToSchema;
use crate::errors::Result;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct VerificationCode {
    /// Verification code unique identifier
    #[schema(example = "ver_550e8400e29b41d4a716446655440000")]
    pub id: String,
    /// Associated user ID
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub user_id: String, 
    /// Email address for verification
    #[schema(example = "user@example.com")]
    pub email: Option<String>,   
    /// Verification code
    #[schema(example = "ABC123DEF456")]
    pub code: String,
    /// Type of verification code
    #[schema(example = "email_verification")]
    pub code_type: String, // Simplify to string for now
    /// Code expiration timestamp
    #[schema(example = "2023-01-01T01:00:00Z")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Code usage timestamp
    #[schema(example = "2023-01-01T00:30:00Z")]
    pub used_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Number of verification attempts
    #[schema(example = 1)]
    pub attempts: i32,
    /// Code creation timestamp
    #[schema(example = "2023-01-01T00:00:00Z")]
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "TEXT")]
pub enum VerificationCodeType {
    #[sqlx(rename = "email_verification")]
    EmailVerification,
    #[sqlx(rename = "password_reset")]
    PasswordReset,
}

impl std::fmt::Display for VerificationCodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationCodeType::EmailVerification => write!(f, "email_verification"),
            VerificationCodeType::PasswordReset => write!(f, "password_reset"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateVerificationCodeRequest {
    pub email: String,
    pub code_type: VerificationCodeType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyCodeRequest {
    pub email: String,
    pub code: String,
    pub code_type: VerificationCodeType,
}

impl VerificationCode {
    pub fn new(
        email: String,
        code_type: String,
        user_id: String,
    ) -> Self {
        let id = Uuid::new_v4().to_string();
        let code = Self::generate_code();
        let now = chrono::Utc::now();
        let expires_at = now + Duration::minutes(15);

        Self {
            id,
            user_id,
            email: Some(email),
            code,
            code_type,
            expires_at,
            used_at: None,
            attempts: 0,
            created_at: now,
        }
    }

    pub fn generate_code() -> String {
        let mut rng = rand::thread_rng();
        (0..6).map(|_| rng.gen_range(0..10).to_string()).collect()
    }

    pub fn is_expired(&self) -> Result<bool> {
        Ok(chrono::Utc::now() > self.expires_at)
    }

    pub fn is_valid(&self) -> Result<bool> {
        Ok(self.used_at.is_none() && !self.is_expired()? && self.attempts < 3)
    }

    pub fn increment_attempts(&mut self) {
        self.attempts += 1;
    }

    pub fn mark_as_used(&mut self) {
        self.used_at = Some(chrono::Utc::now());
    }

    // Database operations will be implemented later
}

// Alias for OpenAPI documentation
pub type EmailVerification = VerificationCode;