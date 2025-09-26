use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use rand::Rng;
use crate::errors::Result;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct VerificationCode {
    pub id: String,
    pub user_id: Option<String>, // Nullable for pre-registration verification
    pub email: Option<String>,   // For codes sent before user creation
    pub code: String,
    pub code_type: VerificationCodeType,
    pub expires_at: String, // SQLite TEXT datetime
    pub used: bool,
    pub attempts: i32,
    pub created_at: String,
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
        code_type: VerificationCodeType,
        user_id: Option<String>,
    ) -> Self {
        let id = Uuid::new_v4().to_string();
        let code = Self::generate_code();
        let now = chrono::Utc::now();
        let expires_at = (now + Duration::minutes(15)).format("%Y-%m-%d %H:%M:%S").to_string();
        let now_str = now.format("%Y-%m-%d %H:%M:%S").to_string();

        Self {
            id,
            user_id,
            email: Some(email),
            code,
            code_type,
            expires_at,
            used: false,
            attempts: 0,
            created_at: now_str,
        }
    }

    pub fn generate_code() -> String {
        let mut rng = rand::thread_rng();
        (0..6).map(|_| rng.gen_range(0..10).to_string()).collect()
    }

    pub fn is_expired(&self) -> Result<bool> {
        let expires_at = chrono::NaiveDateTime::parse_from_str(&self.expires_at, "%Y-%m-%d %H:%M:%S")
            .map_err(|e| crate::errors::AppError::Internal(format!("Invalid datetime format: {}", e)))?;
        let expires_at_utc: DateTime<Utc> = DateTime::from_naive_utc_and_offset(expires_at, Utc);
        Ok(chrono::Utc::now() > expires_at_utc)
    }

    pub fn is_valid(&self) -> Result<bool> {
        Ok(!self.used && !self.is_expired()? && self.attempts < 3)
    }

    pub fn increment_attempts(&mut self) {
        self.attempts += 1;
    }

    pub fn mark_as_used(&mut self) {
        self.used = true;
    }
}