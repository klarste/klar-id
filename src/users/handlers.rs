use actix_web::{web, HttpResponse};
use crate::users::models::{User, KsuidSchema};
use crate::auth::errors::AuthError;
use crate::db::DbPool;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use sqlx::postgres::PgQueryResult;
use log::error;
use svix_ksuid::Ksuid;
use std::str::FromStr;
use sqlx::Row;


#[derive(Deserialize, ToSchema)]
pub struct CreateUserRequest {
    #[schema(example = "unique_username")]
    pub username: String,
    pub firstname: String,
    pub lastname: String,
    #[schema(example = "user@example.com")]
    pub email: Option<String>,
    #[schema(example = "+1234567890")]
    pub phone: Option<String>,
    pub password: String,
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateUserRequest {
    pub firstname: Option<String>,
    pub lastname: Option<String>,
    #[schema(example = "user@example.com")]
    pub email: Option<String>,
    #[schema(example = "+1234567890")]
    pub phone: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Serialize, ToSchema)]
pub struct UserListResponse {
    pub users: Vec<User>,
    pub total: i64,
}

#[derive(Deserialize)]
pub struct ListUsersQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Create a new user
#[utoipa::path(
    post,
    path = "/",
    request_body = CreateUserRequest,
    responses(
        (status = 200, description = "User created successfully", body = User),
        (status = 400, description = "Invalid request"),
        (status = 409, description = "Username, email, or phone already exists")
    )
)]
pub async fn create_user(payload: web::Json<CreateUserRequest>, db_pool: web::Data<DbPool>) -> Result<HttpResponse, AuthError> {
    // Validate request - check for blank or empty fields
    if payload.username.trim().is_empty() {
        return Err(AuthError::InvalidRequest("Username cannot be blank".to_string()));
    }
    
    if payload.firstname.trim().is_empty() || payload.lastname.trim().is_empty() {
        return Err(AuthError::InvalidRequest("First name and last name cannot be blank".to_string()));
    }
    
    if payload.password.trim().is_empty() || payload.password.len() < 8 {
        return Err(AuthError::InvalidRequest("Password must be at least 8 characters".to_string()));
    }
    
    // Validate that at least one contact method is provided
    if payload.email.is_none() && payload.phone.is_none() {
        return Err(AuthError::InvalidRequest("Either email or phone is required".to_string()));
    }
    
    // Validate email format if provided
    if let Some(email) = &payload.email {
        if email.trim().is_empty() {
            return Err(AuthError::InvalidRequest("Email cannot be blank".to_string()));
        }
        
        if !email.contains('@') {
            return Err(AuthError::InvalidRequest("Invalid email format".to_string()));
        }
        
        // In a real application, check if email already exists in database
        // For demo purposes, simulate a check
        if email == "existing@example.com" {
            return Err(AuthError::ResourceExists("Email already registered".to_string()));
        }
    }
    
    // Validate phone format if provided
    if let Some(phone) = &payload.phone {
        if phone.trim().is_empty() {
            return Err(AuthError::InvalidRequest("Phone cannot be blank".to_string()));
        }
        
        // Basic phone validation - should contain only digits and possibly '+' at the start
        if !phone.chars().all(|c| c.is_digit(10) || c == '+') {
            return Err(AuthError::InvalidRequest("Invalid phone format".to_string()));
        }
        
        // In a real application, check if phone already exists in database
        // For demo purposes, simulate a check
        if phone == "+1234567890" {
            return Err(AuthError::ResourceExists("Phone number already registered".to_string()));
        }
    }
    
    // Check username uniqueness
    // In a real application, check if username already exists in database
    // For demo purposes, simulate a check
    if payload.username == "existing_user" {
        return Err(AuthError::ResourceExists("Username already taken".to_string()));
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
    
    // Create the user object
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

/// List all users with pagination
#[utoipa::path(
    get,
    path = "/",
    responses(
        (status = 200, description = "List of users", body = UserListResponse)
    ),
    params(
        ("limit" = Option<i64>, Query, description = "Maximum number of users to return"),
        ("offset" = Option<i64>, Query, description = "Number of users to skip")
    )
)]
pub async fn list_users(query: web::Query<ListUsersQuery>, db_pool: web::Data<DbPool>) -> Result<HttpResponse, AuthError> {
    let limit = query.limit.unwrap_or(10);
    let offset = query.offset.unwrap_or(0);
    
    if limit < 1 || limit > 100 {
        return Err(AuthError::InvalidRequest("Limit must be between 1 and 100".to_string()));
    }
    
    if offset < 0 {
        return Err(AuthError::InvalidRequest("Offset must be non-negative".to_string()));
    }
    
    let pool = db_pool.get_ref();
    
    // Get total count
    let total_count = sqlx::query("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await
        .map_err(|e| {
            error!("Database error counting users: {}", e);
            AuthError::DatabaseError(format!("Error counting users: {}", e))
        })?;

    let total = total_count.get::<i64, _>(0);
    
    // Query users with pagination
    let rows = sqlx::query("SELECT * FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2")
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
        .map_err(|e| {
            error!("Database error fetching users: {}", e);
            AuthError::DatabaseError(format!("Error fetching users: {}", e))
        })?;
    
    let mut users = Vec::with_capacity(rows.len());
    
    for row in rows {
        let id_str = row.get::<String, _>("id");
        let id = Ksuid::from_str(&id_str).map_err(|_| {
            AuthError::DatabaseError("Invalid user ID format in database".to_string())
        })?;
        
        users.push(User {
            id: KsuidSchema(id),
            username: row.get("username"),
            firstname: row.get("firstname"),
            lastname: row.get("lastname"),
            email: row.get("email"),
            email_verified: row.get("email_verified"),
            phone: row.get("phone"),
            phone_verified: row.get("phone_verified"),
            password: row.get("password"),
            enabled: row.get("enabled"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        });
    }
    
    Ok(HttpResponse::Ok().json(UserListResponse { users, total }))
}

/// Get a user by ID
#[utoipa::path(
    get,
    path = "/{user_id}/",
    responses(
        (status = 200, description = "User found", body = User),
        (status = 404, description = "User not found")
    ),
    params(
        ("user_id" = String, Path, description = "User ID")
    )
)]
pub async fn get_user(path: web::Path<String>, db_pool: web::Data<DbPool>) -> Result<HttpResponse, AuthError> {
    let user_id = path.into_inner();
    
    // Validate the user ID format
    if Ksuid::from_str(&user_id).is_err() {
        return Err(AuthError::InvalidRequest("Invalid user ID format".to_string()));
    }
    
    let pool = db_pool.get_ref();
    
    // Query the database for the user
    let row = sqlx::query("SELECT * FROM users WHERE id = $1")
        .bind(&user_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            error!("Database error fetching user: {}", e);
            AuthError::DatabaseError(format!("Error fetching user: {}", e))
        })?;
    
    let user = match row {
        Some(row) => {
            let id_str = row.get::<String, _>("id");
            let id = Ksuid::from_str(&id_str).map_err(|_| {
                AuthError::DatabaseError("Invalid user ID format in database".to_string())
            })?;
            
            Some(User {
                id: KsuidSchema(id),
                username: row.get("username"),
                firstname: row.get("firstname"),
                lastname: row.get("lastname"),
                email: row.get("email"),
                email_verified: row.get("email_verified"),
                phone: row.get("phone"),
                phone_verified: row.get("phone_verified"),
                password: row.get("password"),
                enabled: row.get("enabled"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            })
        },
        None => None
    };
    
    match user {
        Some(user) => Ok(HttpResponse::Ok().json(user)),
        None => Err(AuthError::UserNotFound)
    }
}

/// Update a user
#[utoipa::path(
    patch,
    path = "/{user_id}/",
    request_body = UpdateUserRequest,
    responses(
        (status = 200, description = "User updated successfully", body = User),
        (status = 404, description = "User not found"),
        (status = 400, description = "Invalid request")
    ),
    params(
        ("user_id" = String, Path, description = "User ID")
    )
)]
pub async fn update_user(
    path: web::Path<String>,
    payload: web::Json<UpdateUserRequest>,
    db_pool: web::Data<DbPool>
) -> Result<HttpResponse, AuthError> {
    let user_id = path.into_inner();
    
    // Validate the user ID format
    if Ksuid::from_str(&user_id).is_err() {
        return Err(AuthError::InvalidRequest("Invalid user ID format".to_string()));
    }
    
    let pool = db_pool.get_ref();
    
    // Check if user exists
    let user_exists = sqlx::query("SELECT id FROM users WHERE id = $1")
        .bind(&user_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            error!("Database error checking user: {}", e);
            AuthError::DatabaseError(format!("Error checking user: {}", e))
        })?;
    
    if user_exists.is_none() {
        return Err(AuthError::UserNotFound);
    }
    
    // Validate email format if provided
    if let Some(ref email) = payload.email {
        if !email.is_empty() && !email.contains('@') {
            return Err(AuthError::InvalidRequest("Invalid email format".to_string()));
        }
        
        // Check if email is already used by another user
        let email_exists = sqlx::query("SELECT id FROM users WHERE email = $1 AND id != $2")
            .bind(email)
            .bind(&user_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| {
                error!("Database error checking email: {}", e);
                AuthError::DatabaseError(format!("Error checking email: {}", e))
            })?;
        
        if email_exists.is_some() {
            return Err(AuthError::ResourceExists("Email already registered to another user".to_string()));
        }
    }
    
    // Validate phone format if provided
    if let Some(ref phone) = payload.phone {
        if !phone.is_empty() && !phone.chars().all(|c| c.is_digit(10) || c == '+') {
            return Err(AuthError::InvalidRequest("Invalid phone format".to_string()));
        }
        
        // Check if phone is already used by another user
        let phone_exists = sqlx::query("SELECT id FROM users WHERE phone = $1 AND id != $2")
            .bind(phone)
            .bind(&user_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| {
                error!("Database error checking phone: {}", e);
                AuthError::DatabaseError(format!("Error checking phone: {}", e))
            })?;
        
        if phone_exists.is_some() {
            return Err(AuthError::ResourceExists("Phone number already registered to another user".to_string()));
        }
    }
    
    // Build the update query dynamically
    let mut query = String::from("UPDATE users SET updated_at = NOW()");
    let mut params = vec![user_id.clone()];
    let mut param_index = 2; // Starting from $2 since $1 is user_id
    
    if let Some(ref firstname) = payload.firstname {
        query.push_str(&format!(", firstname = ${}", param_index));
        params.push(firstname.clone());
        param_index += 1;
    }
    
    if let Some(ref lastname) = payload.lastname {
        query.push_str(&format!(", lastname = ${}", param_index));
        params.push(lastname.clone());
        param_index += 1;
    }
    
    if let Some(ref email) = payload.email {
        query.push_str(&format!(", email = ${}", param_index));
        params.push(email.clone());
        param_index += 1;
    }
    
    if let Some(ref phone) = payload.phone {
        query.push_str(&format!(", phone = ${}", param_index));
        params.push(phone.clone());
        param_index += 1;
    }
    
    if let Some(enabled) = payload.enabled {
        query.push_str(&format!(", enabled = ${}", param_index));
        params.push(enabled.to_string());
        //param_index += 1;
    }
    
    query.push_str(" WHERE id = $1 RETURNING *");
    
    // Execute the update query
    let mut q = sqlx::query(&query);
    
    // Bind parameters
    for param in params {
        q = q.bind(param);
    }
    
    // Execute the query
    let row = q.fetch_one(pool).await.map_err(|e| {
        error!("Database error updating user: {}", e);
        AuthError::DatabaseError(format!("Error updating user: {}", e))
    })?;
    
    // Convert row to User struct
    let id_str = row.get::<String, _>("id");
    let id = Ksuid::from_str(&id_str).map_err(|_| {
        AuthError::DatabaseError("Invalid user ID format in database".to_string())
    })?;
    
    let updated_user = User {
        id: KsuidSchema(id),
        username: row.get("username"),
        firstname: row.get("firstname"),
        lastname: row.get("lastname"),
        email: row.get("email"),
        email_verified: row.get("email_verified"),
        phone: row.get("phone"),
        phone_verified: row.get("phone_verified"),
        password: row.get("password"),
        enabled: row.get("enabled"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    };
    
    Ok(HttpResponse::Ok().json(updated_user))
}

/// Delete a user
#[utoipa::path(
    delete,
    path = "/{user_id}/",
    responses(
        (status = 204, description = "User deleted successfully"),
        (status = 404, description = "User not found")
    ),
    params(
        ("user_id" = String, Path, description = "User ID")
    )
)]
pub async fn delete_user(path: web::Path<String>, db_pool: web::Data<DbPool>) -> Result<HttpResponse, AuthError> {
    let user_id = path.into_inner();
    
    // Validate the user ID format
    if Ksuid::from_str(&user_id).is_err() {
        return Err(AuthError::InvalidRequest("Invalid user ID format".to_string()));
    }
    
    let pool = db_pool.get_ref();
    
    // Delete the user
    let result = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(&user_id)
        .execute(pool)
        .await
        .map_err(|e| {
            error!("Database error deleting user: {}", e);
            AuthError::DatabaseError(format!("Error deleting user: {}", e))
        })?;
    
    if result.rows_affected() == 0 {
        return Err(AuthError::UserNotFound);
    }
    
    Ok(HttpResponse::NoContent().finish())
}
