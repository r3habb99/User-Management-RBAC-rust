//! Authentication request models.

use serde::Deserialize;
use utoipa::ToSchema;
use validator::Validate;

use crate::validators::{validate_password_strength, validate_username_format};

/// Request payload for user registration
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct RegisterRequest {
    /// User's email address
    #[validate(email(message = "Invalid email format"))]
    #[schema(example = "user@example.com")]
    pub email: String,
    /// Unique username (3-50 characters, letters, numbers, underscores, hyphens only)
    #[validate(
        length(
            min = 3,
            max = 50,
            message = "Username must be between 3 and 50 characters"
        ),
        custom(function = "validate_username_format")
    )]
    #[schema(example = "johndoe")]
    pub username: String,
    /// Password (minimum 8 characters with uppercase, lowercase, digit, and special character)
    #[validate(custom(function = "validate_password_strength"))]
    #[schema(example = "SecurePass123!")]
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
