use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AccountActivity {
    pub id: String,
    pub user_id: String,
    pub activity_type: ActivityType,
    pub details: Option<String>, // JSON string for additional data
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "TEXT")]
pub enum ActivityType {
    #[sqlx(rename = "login")]
    Login,
    #[sqlx(rename = "logout")]
    Logout,
    #[sqlx(rename = "register")]
    Register,
    #[sqlx(rename = "password_change")]
    PasswordChange,
    #[sqlx(rename = "email_verification")]
    EmailVerification,
    #[sqlx(rename = "password_reset")]
    PasswordReset,
    #[sqlx(rename = "profile_update")]
    ProfileUpdate,
    #[sqlx(rename = "session_revoked")]
    SessionRevoked,
}

impl std::fmt::Display for ActivityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActivityType::Login => write!(f, "login"),
            ActivityType::Logout => write!(f, "logout"),
            ActivityType::Register => write!(f, "register"),
            ActivityType::PasswordChange => write!(f, "password_change"),
            ActivityType::EmailVerification => write!(f, "email_verification"),
            ActivityType::PasswordReset => write!(f, "password_reset"),
            ActivityType::ProfileUpdate => write!(f, "profile_update"),
            ActivityType::SessionRevoked => write!(f, "session_revoked"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityResponse {
    pub id: String,
    pub activity_type: ActivityType,
    pub details: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: String,
}

impl AccountActivity {
    pub fn new(
        user_id: String,
        activity_type: ActivityType,
        ip_address: Option<String>,
        user_agent: Option<String>,
        details: Option<serde_json::Value>,
    ) -> Self {
        let id = Uuid::new_v4().to_string();
        let details_str = details.map(|d| d.to_string());
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        Self {
            id,
            user_id,
            activity_type,
            details: details_str,
            ip_address,
            user_agent,
            created_at: now,
        }
    }

    pub fn to_response(&self) -> crate::errors::Result<ActivityResponse> {
        let details = if let Some(ref details_str) = self.details {
            Some(serde_json::from_str(details_str).map_err(|e| {
                crate::errors::AppError::Internal(format!("Invalid JSON in details: {}", e))
            })?)
        } else {
            None
        };

        Ok(ActivityResponse {
            id: self.id.clone(),
            activity_type: self.activity_type.clone(),
            details,
            ip_address: self.ip_address.clone(),
            user_agent: self.user_agent.clone(),
            created_at: self.created_at.clone(),
        })
    }
}