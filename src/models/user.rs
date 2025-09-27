use crate::services::{PasswordService, PasswordPolicy};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use uuid::Uuid;
use validator::Validate;
use crate::errors::Result;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, Validate)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub email_verified: bool,
    pub email_verified_at: Option<chrono::DateTime<chrono::Utc>>,
    pub avatar_url: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
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
        let id = Uuid::new_v4();
        let password_service = PasswordService::new();
        let policy = PasswordPolicy::default();
        let password_hash = password_service.validate_and_hash(password, &policy)?;
        let now = chrono::Utc::now();

        Ok(Self {
            id,
            email,
            password_hash,
            email_verified: false,
            first_name: None,
            last_name: None,
            email_verified_at: None,
            avatar_url: None,
            created_at: now,
            updated_at: now,
        })
    }

    pub fn verify_password(&self, password: &str) -> Result<bool> {
        let password_service = PasswordService::new();
        password_service.verify_password(password, &self.password_hash)
    }

    pub fn update_password(&mut self, new_password: &str) -> Result<()> {
        let password_service = PasswordService::new();
        let policy = PasswordPolicy::default();
        self.password_hash = password_service.validate_and_hash(new_password, &policy)?;
        self.updated_at = chrono::Utc::now();
        Ok(())
    }

    // Database operations will be implemented later



    pub fn to_response(&self) -> UserResponse {
        UserResponse {
            id: self.id.to_string(),
            email: self.email.clone(),
            email_verified: self.email_verified,
            first_name: self.first_name.clone(),
            last_name: self.last_name.clone(),
            avatar_url: self.avatar_url.clone(),
            created_at: self.created_at.to_string(),
            updated_at: self.updated_at.to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_creation_with_valid_password() {
        let user = User::new("test@example.com".to_string(), "ValidPass123!");
        assert!(user.is_ok());
        
        let user = user.unwrap();
        assert_eq!(user.email, "test@example.com");
        assert!(!user.email_verified);
        assert!(!user.password_hash.is_empty());
    }

    #[test]
    fn test_user_creation_with_invalid_password() {
        // Password too short
        let user = User::new("test@example.com".to_string(), "short");
        assert!(user.is_err());
        
        // Password missing requirements
        let user = User::new("test@example.com".to_string(), "nouppercase123!");
        assert!(user.is_err());
    }

    #[test]
    fn test_password_verification() {
        let user = User::new("test@example.com".to_string(), "ValidPass123!").unwrap();
        
        // Correct password
        assert!(user.verify_password("ValidPass123!").unwrap());
        
        // Wrong password
        assert!(!user.verify_password("WrongPassword").unwrap());
    }

    #[test]
    fn test_password_update() {
        let mut user = User::new("test@example.com".to_string(), "ValidPass123!").unwrap();
        let old_hash = user.password_hash.clone();
        
        // Update password
        assert!(user.update_password("NewValidPass456!").is_ok());
        assert_ne!(user.password_hash, old_hash);
        
        // Verify old password no longer works
        assert!(!user.verify_password("ValidPass123!").unwrap());
        
        // Verify new password works
        assert!(user.verify_password("NewValidPass456!").unwrap());
    }

    #[test]
    fn test_user_to_response() {
        let user = User::new("test@example.com".to_string(), "ValidPass123!").unwrap();
        let response = user.to_response();
        
        assert_eq!(response.email, user.email);
        assert_eq!(response.id, user.id);
        assert_eq!(response.email_verified, user.email_verified);
        // Password hash should not be in response
    }
}