use actix_web::{HttpResponse, ResponseError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Authentication failed: Invalid credentials")]
    InvalidCredentials,

    #[error("Authentication failed: Token expired")]
    TokenExpired,

    #[error("Authentication failed: Invalid token - {0}")]
    InvalidToken(String),

    #[error("Token creation failed: {0}")]
    TokenCreation(String),

    #[error("User not found")]
    UserNotFound,

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Resource already exists: {0}")]
    ResourceExists(String),
}

impl ResponseError for AuthError {
    fn error_response(&self) -> HttpResponse {
        match self {
            AuthError::InvalidCredentials => HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "invalid_credentials",
                "message": "Invalid username/email/phone or password"
            })),
            AuthError::TokenExpired => HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "token_expired",
                "message": "Token has expired"
            })),
            AuthError::InvalidToken(_) => HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "invalid_token",
                "message": "Invalid token"
            })),
            AuthError::UserNotFound => HttpResponse::NotFound().json(serde_json::json!({
                "error": "user_not_found",
                "message": "User not found"
            })),
            AuthError::DatabaseError(msg) => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "database_error",
                    "message": msg
                }))
            }
            AuthError::TokenCreation(msg) => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "token_creation_error",
                    "message": msg
                }))
            }
            AuthError::InvalidRequest(msg) => HttpResponse::BadRequest().json(serde_json::json!({
                "error": "invalid_request",
                "message": msg
            })),
            AuthError::ResourceExists(msg) => HttpResponse::Conflict().json(serde_json::json!({
                "error": "resource_exists",
                "message": msg
            })),
        }
    }
}
