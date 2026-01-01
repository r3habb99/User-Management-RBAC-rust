use chrono::{DateTime, Utc};
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};
use std::fmt;
use utoipa::ToSchema;
use validator::Validate;

/// User roles for role-based access control
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    User,
}

impl Default for Role {
    fn default() -> Self {
        Role::User
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Admin => write!(f, "admin"),
            Role::User => write!(f, "user"),
        }
    }
}

impl Role {
    /// Check if this role has admin privileges
    pub fn is_admin(&self) -> bool {
        matches!(self, Role::Admin)
    }

    /// Parse role from string
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "admin" => Role::Admin,
            _ => Role::User,
        }
    }
}

/// User profile information
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct UserProfile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bio: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_of_birth: Option<String>,
}

/// User document stored in MongoDB
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub email: String,
    pub username: String,
    pub password_hash: String,
    #[serde(default)]
    pub role: Role,
    pub is_active: bool,
    #[serde(default)]
    pub profile: UserProfile,
    pub created_at: mongodb::bson::DateTime,
    pub updated_at: mongodb::bson::DateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_login: Option<mongodb::bson::DateTime>,
}

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

/// Request payload for updating user profile
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateUserRequest {
    /// New email address
    #[validate(email(message = "Invalid email format"))]
    #[schema(example = "newemail@example.com")]
    pub email: Option<String>,
    /// New username (3-50 characters)
    #[validate(length(
        min = 3,
        max = 50,
        message = "Username must be between 3 and 50 characters"
    ))]
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
    #[schema(example = "1990-01-15")]
    pub date_of_birth: Option<String>,
}

/// Request payload for changing password
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ChangePasswordRequest {
    /// Current password for verification
    #[validate(length(min = 1, message = "Current password is required"))]
    #[schema(example = "currentPassword123")]
    pub current_password: String,
    /// New password (minimum 8 characters)
    #[validate(length(min = 8, message = "New password must be at least 8 characters"))]
    #[schema(example = "newSecurePassword456")]
    pub new_password: String,
    /// Confirm new password
    #[validate(length(min = 8, message = "Confirm password must be at least 8 characters"))]
    #[schema(example = "newSecurePassword456")]
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

/// Custom validator for role field
fn validate_role(role: &str) -> Result<(), validator::ValidationError> {
    match role.to_lowercase().as_str() {
        "admin" | "user" => Ok(()),
        _ => {
            let mut error = validator::ValidationError::new("invalid_role");
            error.message = Some("Role must be either 'admin' or 'user'".into());
            Err(error)
        }
    }
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

/// Result of a single user update in bulk operation
#[derive(Debug, Serialize, ToSchema)]
pub struct BulkUpdateResult {
    /// User ID that was updated
    pub user_id: String,
    /// Whether the update was successful
    pub success: bool,
    /// Status message
    pub message: String,
}

/// Response for bulk update operations
#[derive(Debug, Serialize, ToSchema)]
pub struct BulkUpdateResponse {
    /// Total number of users requested to update
    pub total_requested: usize,
    /// Number of successful updates
    pub successful: usize,
    /// Number of failed updates
    pub failed: usize,
    /// Detailed results for each user
    pub results: Vec<BulkUpdateResult>,
}

/// User statistics response (admin only)
#[derive(Debug, Serialize, ToSchema)]
pub struct UserStats {
    /// Total number of users in the system
    pub total_users: u64,
    /// Number of active users
    pub active_users: u64,
    /// Number of inactive users
    pub inactive_users: u64,
    /// Number of admin users
    pub admin_users: u64,
    /// Number of regular users
    pub regular_users: u64,
}

/// Response for successful authentication
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthResponse {
    /// Whether the request was successful
    pub success: bool,
    /// Response message
    pub message: String,
    /// JWT token for authentication
    #[schema(example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")]
    pub token: String,
    /// User information
    pub user: UserResponse,
}

/// User profile data returned in API responses
#[derive(Debug, Serialize, Deserialize, Clone, Default, ToSchema)]
pub struct UserProfileResponse {
    /// User's first name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    /// User's last name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    /// URL to user's avatar image
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    /// User's phone number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    /// User's bio/description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bio: Option<String>,
    /// User's location
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// User's personal website
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    /// User's date of birth
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_of_birth: Option<String>,
}

impl From<UserProfile> for UserProfileResponse {
    fn from(profile: UserProfile) -> Self {
        Self {
            first_name: profile.first_name,
            last_name: profile.last_name,
            avatar_url: profile.avatar_url,
            phone: profile.phone,
            bio: profile.bio,
            location: profile.location,
            website: profile.website,
            date_of_birth: profile.date_of_birth,
        }
    }
}

/// User data returned in API responses (without sensitive fields)
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct UserResponse {
    /// User's unique identifier
    #[schema(example = "507f1f77bcf86cd799439011")]
    pub id: String,
    /// User's email address
    #[schema(example = "user@example.com")]
    pub email: String,
    /// User's username
    #[schema(example = "johndoe")]
    pub username: String,
    /// User's role
    pub role: Role,
    /// Whether the user is active
    #[schema(example = true)]
    pub is_active: bool,
    /// User's profile information
    pub profile: UserProfileResponse,
    /// When the user was created
    pub created_at: DateTime<Utc>,
    /// When the user last logged in
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_login: Option<DateTime<Utc>>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id.map(|id| id.to_hex()).unwrap_or_default(),
            email: user.email,
            username: user.username,
            role: user.role,
            is_active: user.is_active,
            profile: user.profile.into(),
            created_at: DateTime::from_timestamp_millis(user.created_at.timestamp_millis())
                .unwrap_or_default(),
            last_login: user.last_login.map(|dt| {
                DateTime::from_timestamp_millis(dt.timestamp_millis()).unwrap_or_default()
            }),
        }
    }
}

/// Generic API response wrapper
#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn success(message: &str, data: T) -> Self {
        Self {
            success: true,
            message: message.to_string(),
            data: Some(data),
        }
    }

    pub fn message(message: &str) -> ApiResponse<()> {
        ApiResponse {
            success: true,
            message: message.to_string(),
            data: None,
        }
    }
}

/// JWT Claims structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String, // user_id
    pub email: String,
    pub role: String, // user role (admin/user)
    pub exp: usize,   // expiration timestamp
    pub iat: usize,   // issued at timestamp
}

impl Claims {
    /// Check if the claims belong to an admin user
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }

    /// Check if the claims belong to the specified user ID
    pub fn is_user(&self, user_id: &str) -> bool {
        self.sub == user_id
    }

    /// Check if the user can access a resource (either admin or owner)
    pub fn can_access(&self, user_id: &str) -> bool {
        self.is_admin() || self.is_user(user_id)
    }
}

/// Paginated list response
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = PaginatedUserResponse)]
pub struct PaginatedResponse<T: Serialize> {
    /// Whether the request was successful
    pub success: bool,
    /// List of items
    pub data: Vec<T>,
    /// Total number of items
    pub total: u64,
    /// Current page number
    pub page: u64,
    /// Items per page
    pub per_page: u64,
    /// Total number of pages
    pub total_pages: u64,
}

/// Error response structure
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    /// Whether the request was successful (always false for errors)
    #[schema(example = false)]
    pub success: bool,
    /// Error message
    #[schema(example = "An error occurred")]
    pub message: String,
    /// Detailed validation errors (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
}

/// Health check response
#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    /// Health status
    #[schema(example = "OK")]
    pub status: String,
    /// Status message
    #[schema(example = "Server is running")]
    pub message: String,
}
