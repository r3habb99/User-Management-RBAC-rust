//! Authentication request models.

use serde::Deserialize;
use utoipa::ToSchema;
use validator::Validate;

/// Request payload for user registration
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct RegisterRequest {
    /// User's email address
    #[validate(email(message = "Invalid email format"))]
    #[schema(example = "user@example.com")]
    pub email: String,
    /// Unique username (3-50 characters)
    #[validate(length(
        min = 3,
        max = 50,
        message = "Username must be between 3 and 50 characters"
    ))]
    #[schema(example = "johndoe")]
    pub username: String,
    /// Password (minimum 8 characters)
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    #[schema(example = "securePassword123")]
    pub password: String,
}

/// Request payload for user login
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct LoginRequest {
    /// User's email address
    #[validate(email(message = "Invalid email format"))]
    #[schema(example = "user@example.com")]
    pub email: String,
    /// User's password
    #[validate(length(min = 1, message = "Password is required"))]
    #[schema(example = "securePassword123")]
    pub password: String,
}

