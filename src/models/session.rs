use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use crate::errors::Result;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct DeviceSession {
    pub id: String,
    pub user_id: String,
    pub refresh_token: String,
    pub device_fingerprint: String,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub trusted: bool,
    pub expires_at: String, // SQLite TEXT datetime
    pub last_used: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSessionResponse {
    pub id: String,
    pub device_fingerprint: String,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub trusted: bool,
    pub last_used: String,
    pub created_at: String,
    pub is_current: bool, // Indicates if this is the current session
}

impl DeviceSession {
    pub fn new(
        user_id: String,
        refresh_token: String,
        device_fingerprint: String,
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Self {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let expires_at = (now + Duration::days(7)).format("%Y-%m-%d %H:%M:%S").to_string();
        let now_str = now.format("%Y-%m-%d %H:%M:%S").to_string();

        Self {
            id,
            user_id,
            refresh_token,
            device_fingerprint,
            user_agent,
            ip_address,
            trusted: false,
            expires_at,
            last_used: now_str.clone(),
            created_at: now_str,
        }
    }

    pub fn is_expired(&self) -> Result<bool> {
        let expires_at = chrono::NaiveDateTime::parse_from_str(&self.expires_at, "%Y-%m-%d %H:%M:%S")
            .map_err(|e| crate::errors::AppError::Internal(format!("Invalid datetime format: {}", e)))?;
        let expires_at_utc: DateTime<Utc> = DateTime::from_naive_utc_and_offset(expires_at, Utc);
        Ok(chrono::Utc::now() > expires_at_utc)
    }

    pub fn update_last_used(&mut self) {
        self.last_used = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    }

    pub fn to_response(&self, is_current: bool) -> DeviceSessionResponse {
        DeviceSessionResponse {
            id: self.id.clone(),
            device_fingerprint: self.device_fingerprint.clone(),
            user_agent: self.user_agent.clone(),
            ip_address: self.ip_address.clone(),
            trusted: self.trusted,
            last_used: self.last_used.clone(),
            created_at: self.created_at.clone(),
            is_current,
        }
    }
}