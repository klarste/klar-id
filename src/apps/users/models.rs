use serde::{Deserialize, Serialize};
use svix_ksuid::{Ksuid, KsuidLike};
use chrono::{DateTime, Utc};
use utoipa::ToSchema;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;
use rand::rngs::OsRng;


#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(value_type = String, example = "1srOrx2ZWZBpBUvZwXKQmoEYga2")]
pub struct KsuidSchema(pub Ksuid);

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct User {
    pub id: KsuidSchema,
    pub username: String,
    pub firstname: String,
    pub lastname: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub phone: Option<String>,
    pub phone_verified: bool,
    #[serde(skip_serializing)]
    pub password: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    pub fn new(username: String, firstname: String, lastname: String, email: Option<String>, phone: Option<String>, password: String) -> Self {
        Self {
            id: KsuidSchema(Ksuid::new(None, None)),
            username,
            firstname,
            lastname,
            email,
            email_verified: false,
            phone,
            phone_verified: false,
            password: Self::hash_password(&password).unwrap_or_else(|_| String::from("error_hashing_password")),
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
        // Generate a random salt instead of using the environment variable
        // This is more secure and avoids issues with base64 encoding
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        Ok(argon2.hash_password(password.as_bytes(), &salt)?.to_string())
    }

    pub fn verify_password(&self, password: &str) -> bool {
        let parsed_hash = match PasswordHash::new(&self.password) {
            Ok(hash) => hash,
            Err(_) => return false,
        };

        Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok()
    }
}
