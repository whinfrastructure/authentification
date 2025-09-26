use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::errors::{AppError, Result};

/// Claims for access tokens (short-lived, 15 minutes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: String,        // user_id
    pub email: String,      // user email for convenience
    pub exp: i64,          // expiration timestamp
    pub iat: i64,          // issued at timestamp
    pub jti: String,       // JWT ID for revocation
    pub device_id: Option<String>, // device fingerprint
    #[serde(rename = "type")]
    pub token_type: String, // "access"
}

/// Claims for refresh tokens (long-lived, 7 days)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub sub: String,        // user_id
    pub device_id: String,  // device fingerprint (required for refresh)
    pub exp: i64,          // expiration timestamp
    pub iat: i64,          // issued at timestamp
    pub jti: String,       // JWT ID for tracking/revocation
    #[serde(rename = "type")]
    pub token_type: String, // "refresh"
}

/// Token pair returned after successful authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_in: i64,  // seconds
    pub refresh_expires_in: i64, // seconds
    pub token_type: String,      // "Bearer"
}

/// JWT service for token generation and validation
#[derive(Clone)]
pub struct JwtService {
    access_token_secret: EncodingKey,
    refresh_token_secret: EncodingKey,
    decoding_key: DecodingKey,
    access_token_duration: Duration,
    refresh_token_duration: Duration,
}

impl JwtService {
    /// Create a new JWT service with the provided secret
    pub fn new(secret: &str, access_expires_in: i64, refresh_expires_in: i64) -> Result<Self> {
        if secret.len() < 32 {
            return Err(AppError::Config(
                "JWT secret must be at least 32 characters long".to_string()
            ));
        }

        let access_token_secret = EncodingKey::from_secret(secret.as_bytes());
        let refresh_token_secret = EncodingKey::from_secret(secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(secret.as_bytes());
        
        Ok(Self {
            access_token_secret,
            refresh_token_secret,
            decoding_key,
            access_token_duration: Duration::seconds(access_expires_in),
            refresh_token_duration: Duration::seconds(refresh_expires_in),
        })
    }

    /// Generate an access token
    pub fn generate_access_token(
        &self,
        user_id: &str,
        email: &str,
        device_id: Option<&str>,
    ) -> Result<String> {
        let now = Utc::now();
        let exp = (now + self.access_token_duration).timestamp();
        let jti = Uuid::new_v4().to_string();

        let claims = AccessTokenClaims {
            sub: user_id.to_string(),
            email: email.to_string(),
            exp,
            iat: now.timestamp(),
            jti,
            device_id: device_id.map(|d| d.to_string()),
            token_type: "access".to_string(),
        };

        let header = Header::new(Algorithm::HS256);
        encode(&header, &claims, &self.access_token_secret)
            .map_err(|e| AppError::Jwt(e))
    }

    /// Generate a refresh token
    pub fn generate_refresh_token(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<String> {
        let now = Utc::now();
        let exp = (now + self.refresh_token_duration).timestamp();
        let jti = Uuid::new_v4().to_string();

        let claims = RefreshTokenClaims {
            sub: user_id.to_string(),
            device_id: device_id.to_string(),
            exp,
            iat: now.timestamp(),
            jti,
            token_type: "refresh".to_string(),
        };

        let header = Header::new(Algorithm::HS256);
        encode(&header, &claims, &self.refresh_token_secret)
            .map_err(|e| AppError::Jwt(e))
    }

    /// Generate both access and refresh tokens
    pub fn generate_token_pair(
        &self,
        user_id: &str,
        email: &str,
        device_id: &str,
    ) -> Result<TokenPair> {
        let access_token = self.generate_access_token(user_id, email, Some(device_id))?;
        let refresh_token = self.generate_refresh_token(user_id, device_id)?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            access_expires_in: self.access_token_duration.num_seconds(),
            refresh_expires_in: self.refresh_token_duration.num_seconds(),
            token_type: "Bearer".to_string(),
        })
    }

    /// Validate and decode an access token
    pub fn validate_access_token(&self, token: &str) -> Result<AccessTokenClaims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.leeway = 30; // 30 seconds leeway for clock skew
        
        let token_data = decode::<AccessTokenClaims>(token, &self.decoding_key, &validation)
            .map_err(|e| AppError::Jwt(e))?;

        // Verify it's an access token
        if token_data.claims.token_type != "access" {
            return Err(AppError::Authentication("Invalid token type".to_string()));
        }

        Ok(token_data.claims)
    }

    /// Validate and decode a refresh token
    pub fn validate_refresh_token(&self, token: &str) -> Result<RefreshTokenClaims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.leeway = 30; // 30 seconds leeway for clock skew
        
        let token_data = decode::<RefreshTokenClaims>(token, &self.decoding_key, &validation)
            .map_err(|e| AppError::Jwt(e))?;

        // Verify it's a refresh token
        if token_data.claims.token_type != "refresh" {
            return Err(AppError::Authentication("Invalid token type".to_string()));
        }

        Ok(token_data.claims)
    }

    /// Extract token from Authorization header
    pub fn extract_token_from_header(auth_header: &str) -> Result<&str> {
        if !auth_header.starts_with("Bearer ") {
            return Err(AppError::Authentication(
                "Invalid authorization header format".to_string()
            ));
        }

        let token = auth_header.trim_start_matches("Bearer ").trim();
        if token.is_empty() {
            return Err(AppError::Authentication("Missing token".to_string()));
        }

        Ok(token)
    }

    /// Get JWT ID from token without full validation (for revocation checks)
    pub fn get_jti_from_token(&self, token: &str) -> Result<String> {
        // Use insecure decoding to extract JTI without validation
        let token_data = jsonwebtoken::decode::<serde_json::Value>(
            token,
            &DecodingKey::from_secret(&[]), // dummy key
            &Validation::new(Algorithm::HS256),
        );

        match token_data {
            Ok(data) => {
                if let Some(jti) = data.claims.get("jti").and_then(|j| j.as_str()) {
                    Ok(jti.to_string())
                } else {
                    Err(AppError::Jwt(jsonwebtoken::errors::Error::from(
                        jsonwebtoken::errors::ErrorKind::InvalidToken
                    )))
                }
            }
            Err(_) => {
                // Fallback: try to extract without validation
                let parts: Vec<&str> = token.split('.').collect();
                if parts.len() != 3 {
                    return Err(AppError::Authentication("Invalid token format".to_string()));
                }

                let payload = base64::decode_config(parts[1], base64::URL_SAFE_NO_PAD)
                    .map_err(|_| AppError::Authentication("Invalid token encoding".to_string()))?;
                
                let claims: serde_json::Value = serde_json::from_slice(&payload)
                    .map_err(|_| AppError::Authentication("Invalid token payload".to_string()))?;

                claims.get("jti")
                    .and_then(|j| j.as_str())
                    .map(|s| s.to_string())
                    .ok_or_else(|| AppError::Authentication("Missing JTI claim".to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_service() -> JwtService {
        JwtService::new(
            "test-secret-key-that-is-at-least-32-characters-long",
            900,  // 15 minutes
            604800, // 7 days
        ).unwrap()
    }

    #[test]
    fn test_jwt_service_creation() {
        let service = create_test_service();
        assert!(service.access_token_duration.num_seconds() == 900);
        assert!(service.refresh_token_duration.num_seconds() == 604800);
    }

    #[test]
    fn test_jwt_service_creation_with_short_secret() {
        let result = JwtService::new("short", 900, 604800);
        assert!(result.is_err());
    }

    #[test]
    fn test_access_token_generation_and_validation() {
        let service = create_test_service();
        let user_id = "123e4567-e89b-12d3-a456-426614174000";
        let email = "test@example.com";
        let device_id = "device123";

        let token = service.generate_access_token(user_id, email, Some(device_id)).unwrap();
        let claims = service.validate_access_token(&token).unwrap();

        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.email, email);
        assert_eq!(claims.device_id, Some(device_id.to_string()));
        assert_eq!(claims.token_type, "access");
    }

    #[test]
    fn test_refresh_token_generation_and_validation() {
        let service = create_test_service();
        let user_id = "123e4567-e89b-12d3-a456-426614174000";
        let device_id = "device123";

        let token = service.generate_refresh_token(user_id, device_id).unwrap();
        let claims = service.validate_refresh_token(&token).unwrap();

        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.device_id, device_id);
        assert_eq!(claims.token_type, "refresh");
    }

    #[test]
    fn test_token_pair_generation() {
        let service = create_test_service();
        let user_id = "123e4567-e89b-12d3-a456-426614174000";
        let email = "test@example.com";
        let device_id = "device123";

        let pair = service.generate_token_pair(user_id, email, device_id).unwrap();
        
        assert!(!pair.access_token.is_empty());
        assert!(!pair.refresh_token.is_empty());
        assert_eq!(pair.token_type, "Bearer");
        assert_eq!(pair.access_expires_in, 900);
        assert_eq!(pair.refresh_expires_in, 604800);

        // Validate both tokens
        let access_claims = service.validate_access_token(&pair.access_token).unwrap();
        let refresh_claims = service.validate_refresh_token(&pair.refresh_token).unwrap();

        assert_eq!(access_claims.sub, user_id);
        assert_eq!(refresh_claims.sub, user_id);
    }

    #[test]
    fn test_header_token_extraction() {
        let token = JwtService::extract_token_from_header("Bearer abc123").unwrap();
        assert_eq!(token, "abc123");

        let result = JwtService::extract_token_from_header("Basic abc123");
        assert!(result.is_err());

        let result = JwtService::extract_token_from_header("Bearer ");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_token_validation() {
        let service = create_test_service();
        
        let result = service.validate_access_token("invalid.token.here");
        assert!(result.is_err());
        
        let result = service.validate_refresh_token("invalid.token.here");
        assert!(result.is_err());
    }
}