use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use chrono::{DateTime, Utc, Duration};
use crate::errors::Result;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RateLimit {
    pub id: String, // Format: "endpoint:identifier" (e.g., "login:user@example.com", "register:192.168.1.1")
    pub attempts: i32,
    pub window_start: String, // SQLite TEXT datetime
    pub blocked_until: Option<String>, // SQLite TEXT datetime, nullable
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub max_attempts: i32,
    pub window_minutes: i32,
    pub block_minutes: i32,
}

impl RateLimit {
    pub fn new(id: String) -> Self {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        
        Self {
            id,
            attempts: 1,
            window_start: now,
            blocked_until: None,
        }
    }

    pub fn increment_attempts(&mut self, config: &RateLimitConfig) -> Result<()> {
        self.attempts += 1;

        // Check if we need to block
        if self.attempts >= config.max_attempts {
            let block_until = chrono::Utc::now() + Duration::minutes(config.block_minutes as i64);
            self.blocked_until = Some(block_until.format("%Y-%m-%d %H:%M:%S").to_string());
        }

        Ok(())
    }

    pub fn is_blocked(&self) -> Result<bool> {
        if let Some(ref blocked_until_str) = self.blocked_until {
            let blocked_until = chrono::NaiveDateTime::parse_from_str(blocked_until_str, "%Y-%m-%d %H:%M:%S")
                .map_err(|e| crate::errors::AppError::Internal(format!("Invalid datetime format: {}", e)))?;
            let blocked_until_utc = DateTime::from_naive_utc_and_offset(blocked_until, Utc);
            Ok(chrono::Utc::now() < blocked_until_utc)
        } else {
            Ok(false)
        }
    }

    pub fn is_window_expired(&self, config: &RateLimitConfig) -> Result<bool> {
        let window_start = chrono::NaiveDateTime::parse_from_str(&self.window_start, "%Y-%m-%d %H:%M:%S")
            .map_err(|e| crate::errors::AppError::Internal(format!("Invalid datetime format: {}", e)))?;
        let window_start_utc = DateTime::from_naive_utc_and_offset(window_start, Utc);
        let window_end = window_start_utc + Duration::minutes(config.window_minutes as i64);
        Ok(chrono::Utc::now() > window_end)
    }

    pub fn reset_window(&mut self) {
        self.attempts = 1;
        self.window_start = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        self.blocked_until = None;
    }

    pub fn should_allow(&self, config: &RateLimitConfig) -> Result<bool> {
        // If blocked, don't allow
        if self.is_blocked()? {
            return Ok(false);
        }

        // If window expired, allow (will be reset)
        if self.is_window_expired(config)? {
            return Ok(true);
        }

        // Check if under limit
        Ok(self.attempts < config.max_attempts)
    }
}

// Helper function to create rate limit ID
pub fn create_rate_limit_id(endpoint: &str, identifier: &str) -> String {
    format!("{}:{}", endpoint, identifier)
}

// Default rate limit configurations
pub fn get_default_rate_limits() -> std::collections::HashMap<String, RateLimitConfig> {
    let mut limits = std::collections::HashMap::new();
    
    limits.insert("login".to_string(), RateLimitConfig {
        max_attempts: 5,
        window_minutes: 15,
        block_minutes: 60,
    });
    
    limits.insert("register".to_string(), RateLimitConfig {
        max_attempts: 3,
        window_minutes: 60,
        block_minutes: 120,
    });
    
    limits.insert("forgot_password".to_string(), RateLimitConfig {
        max_attempts: 3,
        window_minutes: 60,
        block_minutes: 60,
    });
    
    limits.insert("verify_email".to_string(), RateLimitConfig {
        max_attempts: 5,
        window_minutes: 60,
        block_minutes: 60,
    });

    limits
}