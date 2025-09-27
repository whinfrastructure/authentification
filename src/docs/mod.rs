use utoipa::OpenApi;
use crate::handlers::auth::*;
use crate::models::{user::User, session::{DeviceSession, DeviceSessionResponse}, verification::VerificationCode};
use crate::errors::ApiError;

#[derive(OpenApi)]
#[openapi(
    paths(
        register_handler,
        login_handler,
        logout_handler,
        refresh_handler,
        verify_email_handler,
        forgot_password_handler,
        reset_password_handler,
        get_profile_handler,
        update_profile_handler,
        change_password_handler,
        delete_account_handler
    ),
    components(
        schemas(
            RegisterRequest,
            RegisterResponse,
            LoginRequest,
            LoginResponse,
            RefreshTokenRequest,
            RefreshResponse,
            VerifyEmailQuery,
            ForgotPasswordRequest,
            ResetPasswordRequest,
            UpdateProfileRequest,
            ChangePasswordRequest,
            UserInfo,
            UserResponse,
            MessageResponse,
            ApiError,
            User,
            DeviceSession,
            DeviceSessionResponse,
            VerificationCode
        )
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "auth", description = "Authentication endpoints"),
        (name = "user", description = "User management endpoints")
    ),
    info(
        title = "Authentication API",
        description = "A secure authentication microservice built with Rust and Axum",
        version = "0.1.0",
        contact(
            name = "API Support",
            email = "support@example.com"
        ),
        license(
            name = "MIT",
            url = "https://opensource.org/licenses/MIT"
        )
    ),
    servers(
        (url = "http://localhost:3000", description = "Local development server"),
        (url = "https://api.example.com", description = "Production server")
    )
)]
pub struct ApiDoc;

use utoipa::Modify;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::Http::new(
                        utoipa::openapi::security::HttpAuthScheme::Bearer,
                    )
                ),
            )
        }
    }
}