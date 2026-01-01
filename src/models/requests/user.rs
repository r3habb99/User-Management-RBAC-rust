//! User-related request models.

use serde::Deserialize;
use utoipa::ToSchema;
use validator::Validate;

use crate::validators::{
    validate_date_of_birth, validate_password_strength, validate_role, validate_username_format,
};

/// Request payload for updating user profile
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateUserRequest {
    /// New email address
    #[validate(email(message = "Invalid email format"))]
    #[schema(example = "newemail@example.com")]
    pub email: Option<String>,
    /// New username (3-50 characters, letters, numbers, underscores, hyphens only)
    #[validate(
        length(
            min = 3,
            max = 50,
            message = "Username must be between 3 and 50 characters"
        ),
        custom(function = "validate_username_format")
    )]
    #[schema(example = "newusername")]
    pub username: Option<String>,
    /// First name (max 50 characters)
    #[validate(length(max = 50, message = "First name must be at most 50 characters"))]
    #[schema(example = "John")]
    pub first_name: Option<String>,
    /// Last name (max 50 characters)
    #[validate(length(max = 50, message = "Last name must be at most 50 characters"))]
    #[schema(example = "Doe")]
    pub last_name: Option<String>,
    /// Phone number (max 20 characters)
    #[validate(length(max = 20, message = "Phone must be at most 20 characters"))]
    #[schema(example = "+1234567890")]
    pub phone: Option<String>,
    /// User bio (max 500 characters)
    #[validate(length(max = 500, message = "Bio must be at most 500 characters"))]
    #[schema(example = "Software developer passionate about Rust")]
    pub bio: Option<String>,
    /// Location (max 100 characters)
    #[validate(length(max = 100, message = "Location must be at most 100 characters"))]
    #[schema(example = "San Francisco, CA")]
    pub location: Option<String>,
    /// Personal website URL
    #[validate(url(message = "Website must be a valid URL"))]
    #[schema(example = "https://example.com")]
    pub website: Option<String>,
    /// Date of birth in YYYY-MM-DD format
    #[validate(custom(function = "validate_date_of_birth"))]
    #[schema(example = "1990-01-15")]
    pub date_of_birth: Option<String>,
}

/// Request payload for changing password
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ChangePasswordRequest {
    /// Current password for verification
    #[validate(length(min = 1, message = "Current password is required"))]
    #[schema(example = "CurrentPass123!")]
    pub current_password: String,
    /// New password (minimum 8 characters with uppercase, lowercase, digit, and special character)
    #[validate(custom(function = "validate_password_strength"))]
    #[schema(example = "NewSecurePass456!")]
    pub new_password: String,
    /// Confirm new password
    #[validate(custom(function = "validate_password_strength"))]
    #[schema(example = "NewSecurePass456!")]
    pub confirm_password: String,
}

/// Request payload for updating user role (admin only)
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateRoleRequest {
    /// New role: 'admin' or 'user'
    #[validate(custom(function = "validate_role"))]
    #[schema(example = "admin")]
    pub role: String,
}

/// Request payload for updating user active status (admin only)
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateStatusRequest {
    /// Whether the user should be active
    #[schema(example = true)]
    pub is_active: bool,
}

/// Request payload for bulk updating user status (admin only)
#[derive(Debug, Deserialize, ToSchema)]
pub struct BulkUpdateStatusRequest {
    /// List of user IDs to update
    #[schema(example = json!(["507f1f77bcf86cd799439011", "507f1f77bcf86cd799439012"]))]
    pub user_ids: Vec<String>,
    /// New status to set for all users
    #[schema(example = false)]
    pub is_active: bool,
}
