use argon2::{
    Argon2, 
    PasswordHash, 
    PasswordHasher, 
    PasswordVerifier,
    Algorithm,
    Version,
    Params,
};
use argon2::password_hash::{SaltString, rand_core::OsRng};
use regex::Regex;
use crate::errors::{AppError, Result};

/// Password service for secure hashing and validation
#[derive(Clone)]
pub struct PasswordService {
    argon2: Argon2<'static>,
}

/// Password policy requirements
#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_special_char: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special_char: true,
        }
    }
}

impl PasswordService {
    /// Create a new password service with secure Argon2id configuration
    pub fn new() -> Self {
        // Use Argon2id variant with secure parameters
        let params = Params::new(
            15_000,  // Memory cost (KiB)
            2,       // Time cost (iterations)
            1,       // Parallelism
            Some(32), // Output length
        ).expect("Failed to create Argon2 params");

        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            params,
        );

        Self { argon2 }
    }

    /// Hash a password using Argon2id
    pub fn hash_password(&self, password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        
        let password_hash = self.argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AppError::Internal(format!("Password hashing failed: {}", e)))?
            .to_string();
            
        Ok(password_hash)
    }

    /// Verify a password against its hash
    pub fn verify_password(&self, password: &str, hash: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| AppError::Internal(format!("Invalid password hash format: {}", e)))?;
            
        match self.argon2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Validate password against policy
    pub fn validate_password(&self, password: &str, policy: &PasswordPolicy) -> Result<()> {
        // Check minimum length
        if password.len() < policy.min_length {
            return Err(AppError::Validation(format!(
                "Password must be at least {} characters long", 
                policy.min_length
            )));
        }

        // Check for uppercase letter
        if policy.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            return Err(AppError::Validation(
                "Password must contain at least one uppercase letter".to_string()
            ));
        }

        // Check for lowercase letter
        if policy.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
            return Err(AppError::Validation(
                "Password must contain at least one lowercase letter".to_string()
            ));
        }

        // Check for digit
        if policy.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
            return Err(AppError::Validation(
                "Password must contain at least one digit".to_string()
            ));
        }

        // Check for special character
        if policy.require_special_char {
            let special_chars_regex = Regex::new(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]")
                .map_err(|e| AppError::Internal(format!("Regex compilation error: {}", e)))?;
            
            if !special_chars_regex.is_match(password) {
                return Err(AppError::Validation(
                    "Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)".to_string()
                ));
            }
        }

        Ok(())
    }

    /// Validate and hash password in one step
    pub fn validate_and_hash(&self, password: &str, policy: &PasswordPolicy) -> Result<String> {
        self.validate_password(password, policy)?;
        self.hash_password(password)
    }

    /// Check if password needs to be rehashed (for algorithm upgrades)
    pub fn needs_rehash(&self, hash: &str) -> Result<bool> {
        let _parsed_hash = PasswordHash::new(hash)
            .map_err(|e| AppError::Internal(format!("Invalid password hash format: {}", e)))?;
            
        // For now, we don't need rehashing logic, but this is where it would go
        // You could check algorithm version, parameters, etc.
        Ok(false)
    }
}

impl Default for PasswordService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing_and_verification() {
        let service = PasswordService::new();
        let password = "TestPassword123!";
        
        let hash = service.hash_password(password).expect("Hashing should succeed");
        assert!(service.verify_password(password, &hash).expect("Verification should succeed"));
        assert!(!service.verify_password("wrong_password", &hash).expect("Verification should succeed"));
    }

    #[test]
    fn test_password_policy_validation() {
        let service = PasswordService::new();
        let policy = PasswordPolicy::default();

        // Valid password
        assert!(service.validate_password("ValidPass123!", &policy).is_ok());

        // Too short
        assert!(service.validate_password("Ab1!", &policy).is_err());

        // Missing uppercase
        assert!(service.validate_password("lowercase123!", &policy).is_err());

        // Missing lowercase
        assert!(service.validate_password("UPPERCASE123!", &policy).is_err());

        // Missing digit
        assert!(service.validate_password("NoNumbers!", &policy).is_err());

        // Missing special character
        assert!(service.validate_password("NoSpecialChars123", &policy).is_err());
    }

    #[test]
    fn test_validate_and_hash() {
        let service = PasswordService::new();
        let policy = PasswordPolicy::default();
        let password = "ValidPassword123!";

        let hash = service.validate_and_hash(password, &policy).expect("Should validate and hash");
        assert!(service.verify_password(password, &hash).expect("Should verify"));
    }
}