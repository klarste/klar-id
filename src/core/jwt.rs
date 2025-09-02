use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Duration, Utc};
use std::env;
use svix_ksuid::{Ksuid, KsuidLike};
use crate::core::errors::AuthError;
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,  // Subject (user ID)
    pub exp: i64,     // Expiration time
    pub iat: i64,     // Issued at
    pub jti: String,  // JWT ID
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

// Cache for JWT secrets and expiration times to avoid repeated env lookups
lazy_static::lazy_static! {
    static ref JWT_SECRET: String = env::var("JWT_SECRET")
        .unwrap_or_else(|_| "default_jwt_secret_change_me".to_string());
    static ref JWT_REFRESH_SECRET: String = env::var("JWT_REFRESH_SECRET")
        .unwrap_or_else(|_| "default_jwt_refresh_secret_change_me".to_string());
    static ref JWT_EXPIRATION: i64 = env::var("JWT_EXPIRATION")
        .unwrap_or_else(|_| "3600".to_string())
        .parse::<i64>()
        .unwrap_or(3600); // 1 hour default
    static ref JWT_REFRESH_EXPIRATION: i64 = env::var("JWT_REFRESH_EXPIRATION")
        .unwrap_or_else(|_| "604800".to_string())
        .parse::<i64>()
        .unwrap_or(604800); // 7 days default
}

pub fn create_token(user_id: &str, is_refresh: bool) -> Result<(String, DateTime<Utc>), AuthError> {
    // Use cached values instead of reading from env each time
    let secret = if is_refresh {
        JWT_REFRESH_SECRET.as_str()
    } else {
        JWT_SECRET.as_str()
    };

    let expiration_seconds = if is_refresh {
        *JWT_REFRESH_EXPIRATION
    } else {
        *JWT_EXPIRATION
    };

    let now = Utc::now();
    let expiry = now + Duration::seconds(expiration_seconds);
    
    let claims = Claims {
        sub: user_id.to_string(),
        exp: expiry.timestamp(),
        iat: now.timestamp(),
        jti: Ksuid::new(None, None).to_string(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    ).map_err(|e| AuthError::TokenCreation(e.to_string()))?;

    Ok((token, expiry))
}

pub fn verify_token(token: &str, is_refresh: bool) -> Result<Claims, AuthError> {
    // Use cached values instead of reading from env each time
    let secret = if is_refresh {
        JWT_REFRESH_SECRET.as_str()
    } else {
        JWT_SECRET.as_str()
    };

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    ).map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
        _ => AuthError::InvalidToken(e.to_string()),
    })?;

    Ok(token_data.claims)
}

pub fn create_token_pair(user_id: &str) -> Result<TokenPair, AuthError> {
    let (access_token, expiry) = create_token(user_id, false)?;
    let (refresh_token, _) = create_token(user_id, true)?;
    
    let expires_in = (expiry - Utc::now()).num_seconds();
    
    Ok(TokenPair {
        access_token,
        refresh_token,
        token_type: "Bearer".to_string(),
        expires_in,
    })
}