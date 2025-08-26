use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;
use utoipa::ToSchema;
use crate::users::models::{User, KsuidSchema};
use crate::auth::jwt::{create_token_pair, verify_token, TokenPair};
use crate::auth::errors::AuthError;
use crate::db::DbPool;
use chrono::{Utc, DateTime};
use svix_ksuid::Ksuid;
use sqlx::postgres::PgQueryResult;
use sqlx::Row;
use log::error;
use std::str::FromStr;


// We'll use a tuple instead of a struct for simplicity

#[derive(Deserialize, ToSchema)]
pub struct RegisterRequest {
    pub username: String,
    pub firstname: String,
    pub lastname: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub password: String,
}

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest {
    #[schema(example = "username_or_email@example.com_or_phone")]
    pub username: String,  // Can be username, email, or phone
    pub password: String,
}

// Helper function to determine identifier type
fn get_identifier_type(identifier: &str) -> &'static str {
    if identifier.contains('@') {
        "email"
    } else if identifier.starts_with("+") || identifier.chars().all(|c| c.is_digit(10) || c == '+') {
        "phone"
    } else {
        "username"
    }
}

#[derive(Deserialize, ToSchema)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

/// Register a new user
#[utoipa::path(
    post,
    path = "/register/",
    request_body = RegisterRequest,
    responses(
        (status = 200, description = "User registered successfully", body = User)
    )
)]
pub async fn register(payload: web::Json<RegisterRequest>, db_pool: web::Data<DbPool>) -> Result<HttpResponse, AuthError> {
    // Validate request
    if payload.email.is_none() && payload.phone.is_none() {
        return Err(AuthError::InvalidRequest("Either email or phone is required".to_string()));
    }
    
    // Get database pool from app data
    let pool = db_pool.get_ref();
    
    // Check if username already exists
    let username_exists = sqlx::query("SELECT username FROM users WHERE username = $1")
        .bind(&payload.username)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            error!("Database error checking username: {}", e);
            AuthError::DatabaseError(format!("Error checking username: {}", e))
        })?;
    
    if username_exists.is_some() {
        return Err(AuthError::ResourceExists("Username already taken".to_string()));
    }
    
    // Check if email already exists (if provided)
    if let Some(email) = &payload.email {
        if !email.trim().is_empty() {
            let email_exists = sqlx::query("SELECT email FROM users WHERE email = $1")
                .bind(email)
                .fetch_optional(pool)
                .await
                .map_err(|e| {
                    error!("Database error checking email: {}", e);
                    AuthError::DatabaseError(format!("Error checking email: {}", e))
                })?;
            
            if email_exists.is_some() {
                return Err(AuthError::ResourceExists("Email already registered".to_string()));
            }
        }
    }
    
    // Check if phone already exists (if provided)
    if let Some(phone) = &payload.phone {
        if !phone.trim().is_empty() {
            let phone_exists = sqlx::query("SELECT phone FROM users WHERE phone = $1")
                .bind(phone)
                .fetch_optional(pool)
                .await
                .map_err(|e| {
                    error!("Database error checking phone: {}", e);
                    AuthError::DatabaseError(format!("Error checking phone: {}", e))
                })?;
            
            if phone_exists.is_some() {
                return Err(AuthError::ResourceExists("Phone number already registered".to_string()));
            }
        }
    }
    
    let user = User::new(
        payload.username.clone(),
        payload.firstname.clone(),
        payload.lastname.clone(),
        payload.email.clone(),
        payload.phone.clone(),
        payload.password.clone(),
    );
    
    // Insert user into database
    let result: Result<PgQueryResult, sqlx::Error> = sqlx::query(
        "INSERT INTO users (id, username, firstname, lastname, email, email_verified, phone, phone_verified, password, enabled, created_at, updated_at) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"
    )
    .bind(user.id.0.to_string())
    .bind(&user.username)
    .bind(&user.firstname)
    .bind(&user.lastname)
    .bind(&user.email)
    .bind(user.email_verified)
    .bind(&user.phone)
    .bind(user.phone_verified)
    .bind(&user.password)
    .bind(user.enabled)
    .bind(user.created_at)
    .bind(user.updated_at)
    .execute(pool)
    .await;
    
    match result {
        Ok(_) => Ok(HttpResponse::Ok().json(user)),
        Err(e) => {
            error!("Database error inserting user: {}", e);
            Err(AuthError::DatabaseError(format!("Error creating user: {}", e)))
        }
    }
}

/// Login user
#[utoipa::path(
    post,
    path = "/login/",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = TokenPair),
        (status = 401, description = "Invalid credentials"),
        (status = 400, description = "Invalid request")
    )
)]
pub async fn login(payload: web::Json<LoginRequest>, db_pool: web::Data<DbPool>) -> Result<HttpResponse, AuthError> {
    // Validate that username is not blank
    if payload.username.trim().is_empty() {
        return Err(AuthError::InvalidRequest("Username/Email/Phone cannot be blank".to_string()));
    }
    
    // Determine the type of identifier (username, email, or phone)
    let identifier_type = get_identifier_type(&payload.username);
    
    // Optimize by avoiding unnecessary logging in production
    #[cfg(debug_assertions)]
    println!("Attempting login with {} identifier: {}", identifier_type, payload.username);
    
    // Get database pool from app data
    let pool = db_pool.get_ref();
    
    // Query the database based on the identifier type
    let user_row_result = match identifier_type {
        "username" => {
            sqlx::query(
                "SELECT id, username, firstname, lastname, email, email_verified, phone, phone_verified, password, enabled, created_at, updated_at 
                FROM users WHERE username = $1 LIMIT 1"
            )
            .bind(&payload.username)
            .fetch_optional(pool)
            .await
        },
        "email" => {
            sqlx::query(
                "SELECT id, username, firstname, lastname, email, email_verified, phone, phone_verified, password, enabled, created_at, updated_at 
                FROM users WHERE email = $1 LIMIT 1"
            )
            .bind(&payload.username)
            .fetch_optional(pool)
            .await
        },
        "phone" => {
            sqlx::query(
                "SELECT id, username, firstname, lastname, email, email_verified, phone, phone_verified, password, enabled, created_at, updated_at 
                FROM users WHERE phone = $1 LIMIT 1"
            )
            .bind(&payload.username)
            .fetch_optional(pool)
            .await
        },
        _ => unreachable!(),
    };
    
    // Handle database errors
    let user_row = match user_row_result {
        Ok(Some(row)) => row,
        Ok(None) => return Err(AuthError::UserNotFound),
        Err(e) => {
            error!("Database error during login: {}", e);
            return Err(AuthError::DatabaseError(format!("Error during login: {}", e)));
        }
    };
    
    // Extract user data from the row and create a User object
     let id_str: String = user_row.try_get("id")
         .map_err(|e| AuthError::DatabaseError(format!("Error extracting id: {}", e)))?;
     let ksuid = Ksuid::from_str(&id_str)
         .map_err(|e| AuthError::DatabaseError(format!("Error parsing id: {}", e)))?;
     
     let user = User {
         id: KsuidSchema(ksuid),
         username: user_row.try_get("username")
             .map_err(|e| AuthError::DatabaseError(format!("Error extracting username: {}", e)))?,
         firstname: user_row.try_get("firstname")
             .map_err(|e| AuthError::DatabaseError(format!("Error extracting firstname: {}", e)))?,
         lastname: user_row.try_get("lastname")
             .map_err(|e| AuthError::DatabaseError(format!("Error extracting lastname: {}", e)))?,
         email: user_row.try_get("email")
             .map_err(|e| AuthError::DatabaseError(format!("Error extracting email: {}", e)))?,
         email_verified: user_row.try_get("email_verified")
             .map_err(|e| AuthError::DatabaseError(format!("Error extracting email_verified: {}", e)))?,
         phone: user_row.try_get("phone")
             .map_err(|e| AuthError::DatabaseError(format!("Error extracting phone: {}", e)))?,
         phone_verified: user_row.try_get("phone_verified")
             .map_err(|e| AuthError::DatabaseError(format!("Error extracting phone_verified: {}", e)))?,
         password: user_row.try_get("password")
             .map_err(|e| AuthError::DatabaseError(format!("Error extracting password: {}", e)))?,
         enabled: user_row.try_get("enabled")
             .map_err(|e| AuthError::DatabaseError(format!("Error extracting enabled: {}", e)))?,
         created_at: user_row.try_get("created_at")
             .map_err(|e| AuthError::DatabaseError(format!("Error extracting created_at: {}", e)))?,
         updated_at: user_row.try_get("updated_at")
             .map_err(|e| AuthError::DatabaseError(format!("Error extracting updated_at: {}", e)))?,
     };
    
    // Verify password - this is a CPU-intensive operation
    // In a production environment, consider rate limiting login attempts
    if !user.verify_password(&payload.password) {
        return Err(AuthError::InvalidCredentials);
    }
    
    // Generate token pair - optimize by avoiding unnecessary allocations
    let user_id = &user.id.0.to_string();
    let token_pair = create_token_pair(user_id)?;
    
    // // In a real application, you would save the refresh token to the database
    // use crate::auth::models::RefreshToken;
    
    // let refresh_token = RefreshToken::new(
    //     user.id.clone(),
    //     token_pair.refresh_token.clone(),
    //     Utc::now() + chrono::Duration::seconds(token_pair.expires_in),
    // );
    
    // // Save refresh token to database
    // let result = sqlx::query(
    //     "INSERT INTO refresh_tokens (id, user_id, token, expires_at, created_at) 
    //      VALUES ($1, $2, $3, $4, $5)"
    // )
    // .bind(refresh_token.id.0.to_string())
    // .bind(refresh_token.user_id.0.to_string())
    // .bind(&refresh_token.token)
    // .bind(refresh_token.expires_at)
    // .bind(refresh_token.created_at)
    // .execute(pool)
    // .await;
    
    // if let Err(e) = result {
    //     error!("Error saving refresh token: {}", e);
    //     // Continue even if saving refresh token fails, as we can still return the token pair
    // }
    
    // // Only log in debug mode to avoid performance impact
    // #[cfg(debug_assertions)]
    // println!("Created refresh token with ID: {}", refresh_token.id.0.to_string());
    
    // Return the token pair without any additional processing
    Ok(HttpResponse::Ok().json(token_pair))
}

/// Refresh access token
#[utoipa::path(
    post,
    path = "/refresh/",
    request_body = RefreshTokenRequest,
    responses(
        (status = 200, description = "Token refreshed successfully", body = TokenPair),
        (status = 401, description = "Invalid refresh token")
    )
)]
pub async fn refresh_token(payload: web::Json<RefreshTokenRequest>, db_pool: web::Data<DbPool>) -> Result<HttpResponse, AuthError> {
    // Verify refresh token
    let claims = verify_token(&payload.refresh_token, true)?;
    
    // Get database pool from app data
    let pool = db_pool.as_ref();
    
    // Check if the refresh token exists in the database and hasn't been revoked
    let token_result = sqlx::query(
        "SELECT id, user_id, expires_at FROM refresh_tokens WHERE token = $1"
    )
    .bind(&payload.refresh_token)
    .fetch_optional(pool)
    .await;
    
    let token_row = match token_result {
        Ok(Some(row)) => row,
        Ok(None) => return Err(AuthError::InvalidToken("Refresh token not found".to_string())),
        Err(e) => {
            error!("Database error checking refresh token: {}", e);
            return Err(AuthError::DatabaseError(format!("Error checking refresh token: {}", e)));
        }
    };
    
    // Extract values from the row
    let token_id: String = token_row.try_get("id")
        .map_err(|e| AuthError::DatabaseError(format!("Error extracting token id: {}", e)))?;
    let user_id: String = token_row.try_get("user_id")
        .map_err(|e| AuthError::DatabaseError(format!("Error extracting user_id: {}", e)))?;
    let expires_at: DateTime<Utc> = token_row.try_get("expires_at")
        .map_err(|e| AuthError::DatabaseError(format!("Error extracting expires_at: {}", e)))?;
    
    // Check if token has expired
    let now = Utc::now();
    if expires_at < now {
        // Delete expired token
        let _ = sqlx::query("DELETE FROM refresh_tokens WHERE id = $1")
            .bind(&token_id)
            .execute(pool)
            .await;
        return Err(AuthError::TokenExpired);
    }
    
    // Verify that the user ID in the token matches the one in the database
    if user_id != claims.sub {
        return Err(AuthError::InvalidToken("Token mismatch".to_string()));
    }
    
    // Generate new token pair
    let token_pair = create_token_pair(&claims.sub)?;
    
    // Update the refresh token in the database
    let new_expires_at = Utc::now() + chrono::Duration::seconds(token_pair.expires_in);
    let refresh_token = token_pair.refresh_token.clone(); // Clone to avoid partial move
    
    let update_result = sqlx::query(
        "UPDATE refresh_tokens SET token = $1, expires_at = $2 WHERE id = $3"
    )
    .bind(refresh_token)
    .bind(new_expires_at)
    .bind(&token_id)
    .execute(pool)
    .await;
    
    if let Err(e) = update_result {
        error!("Error updating refresh token: {}", e);
        // Continue even if updating refresh token fails, as we can still return the token pair
    }
    
    Ok(HttpResponse::Ok().json(token_pair))
}

/// Logout user
#[utoipa::path(
    post,
    path = "/logout/",
    responses(
        (status = 200, description = "Logout successful")
    )
)]
pub async fn logout(refresh_token: Option<web::Json<RefreshTokenRequest>>, db_pool: web::Data<DbPool>) -> impl Responder {
    // If refresh token is provided, invalidate it in the database
    if let Some(token_data) = refresh_token {
        let pool = db_pool.get_ref();
        
        // Delete the refresh token from the database
        let delete_result = sqlx::query("DELETE FROM refresh_tokens WHERE token = $1")
            .bind(&token_data.refresh_token)
            .execute(pool)
            .await;
        
        if let Err(e) = delete_result {
            error!("Error deleting refresh token: {}", e);
            // Continue even if deleting refresh token fails
        }
    }
    
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Logged out successfully"
    }))
}