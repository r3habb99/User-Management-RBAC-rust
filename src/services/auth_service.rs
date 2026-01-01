//! Authentication service for login, token generation, and password utilities.

use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use log::debug;
use mongodb::bson::doc;
use mongodb::{Collection, Database};

use crate::config::CONFIG;
use crate::errors::ApiError;
use crate::models::{Claims, LoginRequest, User};

/// Service for authentication operations.
pub struct AuthService {
    collection: Collection<User>,
}

impl AuthService {
    /// Create a new AuthService instance.
    pub fn new(db: &Database) -> Self {
        Self {
            collection: db.collection("users"),
        }
    }

    /// Authenticate a user and return a JWT token.
    pub async fn login(&self, req: LoginRequest) -> Result<(User, String), ApiError> {
        let user = self
            .find_by_email(&req.email)
            .await?
            .ok_or_else(|| ApiError::Unauthorized("Invalid email or password".to_string()))?;

        if !user.is_active {
            return Err(ApiError::Unauthorized("Account is deactivated".to_string()));
        }

        // Verify password
        if !verify_password(&req.password, &user.password_hash)? {
            return Err(ApiError::Unauthorized(
                "Invalid email or password".to_string(),
            ));
        }

        // Update last login
        let user_id = user.id.unwrap();
        self.collection
            .update_one(
                doc! { "_id": user_id },
                doc! { "$set": { "last_login": mongodb::bson::DateTime::now() } },
            )
            .await?;

        // Generate JWT token
        let token = generate_token(&user)?;

        Ok((user, token))
    }

    /// Find a user by email.
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, ApiError> {
        Ok(self
            .collection
            .find_one(doc! { "email": email.to_lowercase() })
            .await?)
    }
}

/// Hash a password using bcrypt.
pub fn hash_password(password: &str) -> Result<String, ApiError> {
    Ok(hash(password, DEFAULT_COST)?)
}

/// Verify a password against a bcrypt hash.
pub fn verify_password(password: &str, hash: &str) -> Result<bool, ApiError> {
    Ok(verify(password, hash)?)
}

/// Generate a JWT token for a user.
pub fn generate_token(user: &User) -> Result<String, ApiError> {
    let now = Utc::now().timestamp() as usize;
    let exp = now + (CONFIG.jwt_expiration_hours as usize * 3600);

    let claims = Claims {
        sub: user.id.unwrap().to_hex(),
        email: user.email.clone(),
        role: user.role.to_string(),
        exp,
        iat: now,
    };

    debug!(
        "Generated token for user {} with role {}",
        user.email, user.role
    );

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(CONFIG.jwt_secret.as_bytes()),
    )?;

    Ok(token)
}

