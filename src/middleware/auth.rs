use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use uuid::Uuid;

use crate::{
    errors::AppError,
    AppState,
};

#[derive(Debug, Clone)]
pub struct UserContext {
    pub user_id: Uuid,
    pub device_id: Option<Uuid>,
}

pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Extract authorization header
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| AppError::Authentication("Missing authorization header".to_string()))?;

    // Extract token from "Bearer <token>"
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Authentication("Invalid authorization format".to_string()))?;

    // Validate token and get claims
    let claims = state.jwt_service.validate_access_token(token)?;
    
    // Parse user ID
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Authentication("Invalid user ID in token".to_string()))?;
    
    // Parse device ID if present
    let device_id = claims.device_id
        .as_ref()
        .and_then(|id| Uuid::parse_str(id).ok());

    // Create user context
    let user_context = UserContext {
        user_id,
        device_id,
    };

    // Add user context to request extensions
    req.extensions_mut().insert(user_context);

    // Continue to the next middleware/handler
    Ok(next.run(req).await)
}