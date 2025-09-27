use utoipa::OpenApi;
use crate::handlers::auth::*;
use crate::models::{user::*, session::*, verification::*};
use crate::errors::AppError;

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
            LoginRequest,
            RefreshRequest,
            VerifyEmailRequest,
            ForgotPasswordRequest,
            ResetPasswordRequest,
            UpdateProfileRequest,
            ChangePasswordRequest,
            AuthResponse,
            UserResponse,
            MessageResponse,
            AppError,
            User,
            Session,
            EmailVerification
        )
    ),
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