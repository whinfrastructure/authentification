pub mod config;
pub mod models;
pub mod handlers;
pub mod services;
pub mod middleware;
pub mod database;
pub mod utils;
pub mod errors;

// Re-exports for convenience
pub use config::*;
pub use database::*;
pub use errors::*;
pub use services::jwt::JwtService;
pub use services::email::EmailService;
pub use services::password::PasswordService;

// App state structure
#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub database: Database,
    pub jwt_service: JwtService,
    pub email_service: EmailService,
    pub password_service: PasswordService,
}