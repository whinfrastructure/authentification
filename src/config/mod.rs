use serde::Deserialize;
use std::env;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub database_url: String,
    pub redis_url: String,
    pub jwt_secret: String,
    pub jwt_access_token_expires_in: i64,
    pub jwt_refresh_token_expires_in: i64,
    pub smtp_server: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub smtp_from_email: String,
    pub smtp_from_name: String,
    pub server_host: String,
    pub server_port: u16,
    pub cors_origins: Vec<String>,
    pub app_name: String,
    pub app_env: String,
    pub log_level: String,
    pub rate_limit_enabled: bool,
}

impl Config {
    pub fn from_env() -> Result<Self, env::VarError> {
        dotenv::dotenv().ok();
        
        Ok(Config {
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite:./auth.db".to_string()),
            redis_url: env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string()),
            jwt_secret: env::var("JWT_SECRET")?,
            jwt_access_token_expires_in: env::var("JWT_ACCESS_TOKEN_EXPIRES_IN")
                .unwrap_or_else(|_| "900".to_string())
                .parse()
                .unwrap_or(900),
            jwt_refresh_token_expires_in: env::var("JWT_REFRESH_TOKEN_EXPIRES_IN")
                .unwrap_or_else(|_| "604800".to_string())
                .parse()
                .unwrap_or(604800),
            smtp_server: env::var("SMTP_SERVER")
                .unwrap_or_else(|_| "smtp.gmail.com".to_string()),
            smtp_port: env::var("SMTP_PORT")
                .unwrap_or_else(|_| "587".to_string())
                .parse()
                .unwrap_or(587),
            smtp_username: env::var("SMTP_USERNAME")?,
            smtp_password: env::var("SMTP_PASSWORD")?,
            smtp_from_email: env::var("SMTP_FROM_EMAIL")?,
            smtp_from_name: env::var("SMTP_FROM_NAME")
                .unwrap_or_else(|_| "Auth Microservice".to_string()),
            server_host: env::var("SERVER_HOST")
                .unwrap_or_else(|_| "127.0.0.1".to_string()),
            server_port: env::var("SERVER_PORT")
                .unwrap_or_else(|_| "3001".to_string())
                .parse()
                .unwrap_or(3001),
            cors_origins: env::var("CORS_ORIGINS")
                .unwrap_or_else(|_| "http://localhost:3000,http://localhost:3001".to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
            app_name: env::var("APP_NAME")
                .unwrap_or_else(|_| "Auth Microservice".to_string()),
            app_env: env::var("APP_ENV")
                .unwrap_or_else(|_| "development".to_string()),
            log_level: env::var("LOG_LEVEL")
                .unwrap_or_else(|_| "debug".to_string()),
            rate_limit_enabled: env::var("RATE_LIMIT_ENABLED")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
        })
    }
}