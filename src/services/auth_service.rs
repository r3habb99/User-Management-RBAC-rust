//! Authentication service for login, token generation, and password utilities.

use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use log::debug;
use mongodb::Database;
use std::sync::Arc;

use crate::config::CONFIG;
use crate::constants::{
    CODE_ACCOUNT_DEACTIVATED, CODE_INVALID_CREDENTIALS, ERR_ACCOUNT_DEACTIVATED,
    ERR_INVALID_CREDENTIALS,
};
use crate::errors::ApiError;
use crate::models::{Claims, LoginRequest, User};
use crate::repositories::UserRepository;
use crate::utils::mask_email;

/// Service for authentication operations.
pub struct AuthService {
    repository: Arc<UserRepository>,
}

impl AuthService {
    /// Create a new AuthService instance.
    pub fn new(db: &Database) -> Self {
        Self {
            repository: Arc::new(UserRepository::new(db)),
        }
    }

    /// Create a new AuthService with a shared repository (for dependency injection).
    #[allow(dead_code)]
    pub fn with_repository(repository: Arc<UserRepository>) -> Self {
        Self { repository }
    }

    /// Authenticate a user and return a JWT token.
    pub async fn login(&self, req: LoginRequest) -> Result<(User, String), ApiError> {
        let user = self
            .repository
            .find_by_email(&req.email)
            .await?
            .ok_or_else(|| ApiError::Unauthorized {
                code: CODE_INVALID_CREDENTIALS.to_string(),
                message: ERR_INVALID_CREDENTIALS.to_string(),
            })?;

        if !user.is_active {
            return Err(ApiError::Unauthorized {
                code: CODE_ACCOUNT_DEACTIVATED.to_string(),
                message: ERR_ACCOUNT_DEACTIVATED.to_string(),
            });
        }

        // Verify password
        if !verify_password(&req.password, &user.password_hash)? {
            return Err(ApiError::Unauthorized {
                code: CODE_INVALID_CREDENTIALS.to_string(),
                message: ERR_INVALID_CREDENTIALS.to_string(),
            });
        }

        // Update last login
        let user_id = user.id.unwrap();
        self.repository.update_last_login(user_id).await?;

        // Generate JWT token
        let token = generate_token(&user)?;

        Ok((user, token))
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
        mask_email(&user.email),
        user.role
    );

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(CONFIG.jwt_secret.as_bytes()),
    )?;

    Ok(token)
}
