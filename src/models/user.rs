use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, rand_core::OsRng};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use validator::Validate;
use crate::errors::{AppError, Result};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, Validate)]
pub struct User {
    pub id: String, // SQLite uses TEXT for UUID
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[serde(skip_serializing)] // Never serialize password hash
    pub password_hash: String,
    pub email_verified: bool,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar_url: Option<String>,
    pub created_at: String, // SQLite TEXT datetime
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct CreateUserRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    #[validate(custom(function = "validate_password_strength"))]
    pub password: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub email_verified: bool,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar_url: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl User {
    pub fn new(email: String, password: &str) -> Result<Self> {
        let id = Uuid::new_v4().to_string();
        let password_hash = Self::hash_password(password)?;
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        Ok(Self {
            id,
            email,
            password_hash,
            email_verified: false,
            first_name: None,
            last_name: None,
            avatar_url: None,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub fn hash_password(password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AppError::Internal(format!("Password hashing failed: {}", e)))?
            .to_string();
        Ok(password_hash)
    }

    pub fn verify_password(&self, password: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(&self.password_hash)
            .map_err(|e| AppError::Internal(format!("Invalid password hash: {}", e)))?;
        let argon2 = Argon2::default();
        Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
    }

    pub fn to_response(&self) -> UserResponse {
        UserResponse {
            id: self.id.clone(),
            email: self.email.clone(),
            email_verified: self.email_verified,
            first_name: self.first_name.clone(),
            last_name: self.last_name.clone(),
            avatar_url: self.avatar_url.clone(),
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
        }
    }
}

// Custom password strength validator
fn validate_password_strength(password: &str) -> std::result::Result<(), validator::ValidationError> {
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut has_special = false;

    for c in password.chars() {
        if c.is_uppercase() {
            has_upper = true;
        } else if c.is_lowercase() {
            has_lower = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else if "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c) {
            has_special = true;
        }
    }

    if !has_upper || !has_lower || !has_digit || !has_special {
        return Err(validator::ValidationError::new("password_strength")
            .with_message("Password must contain uppercase, lowercase, digit and special character".into()));
    }

    Ok(())
}