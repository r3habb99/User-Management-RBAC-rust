use chrono::{DateTime, Utc};
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};
use std::fmt;
use validator::Validate;

/// User roles for role-based access control
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
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
#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(
        min = 3,
        max = 50,
        message = "Username must be between 3 and 50 characters"
    ))]
    pub username: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
}

/// Request payload for user login
#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
}

/// Request payload for updating user profile
#[derive(Debug, Deserialize, Validate)]
pub struct UpdateUserRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: Option<String>,
    #[validate(length(
        min = 3,
        max = 50,
        message = "Username must be between 3 and 50 characters"
    ))]
    pub username: Option<String>,
    #[validate(length(max = 50, message = "First name must be at most 50 characters"))]
    pub first_name: Option<String>,
    #[validate(length(max = 50, message = "Last name must be at most 50 characters"))]
    pub last_name: Option<String>,
    #[validate(length(max = 20, message = "Phone must be at most 20 characters"))]
    pub phone: Option<String>,
    #[validate(length(max = 500, message = "Bio must be at most 500 characters"))]
    pub bio: Option<String>,
    #[validate(length(max = 100, message = "Location must be at most 100 characters"))]
    pub location: Option<String>,
    #[validate(url(message = "Website must be a valid URL"))]
    pub website: Option<String>,
    /// Date of birth in YYYY-MM-DD format
    pub date_of_birth: Option<String>,
}

/// Request payload for changing password
#[derive(Debug, Deserialize, Validate)]
pub struct ChangePasswordRequest {
    #[validate(length(min = 1, message = "Current password is required"))]
    pub current_password: String,
    #[validate(length(min = 8, message = "New password must be at least 8 characters"))]
    pub new_password: String,
    #[validate(length(min = 8, message = "Confirm password must be at least 8 characters"))]
    pub confirm_password: String,
}

/// Request payload for updating user role (admin only)
#[derive(Debug, Deserialize, Validate)]
pub struct UpdateRoleRequest {
    #[validate(custom(function = "validate_role"))]
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
#[derive(Debug, Deserialize)]
pub struct UpdateStatusRequest {
    pub is_active: bool,
}

/// Request payload for bulk updating user status (admin only)
#[derive(Debug, Deserialize)]
pub struct BulkUpdateStatusRequest {
    /// List of user IDs to update
    pub user_ids: Vec<String>,
    /// New status to set for all users
    pub is_active: bool,
}

/// Result of a single user update in bulk operation
#[derive(Debug, Serialize)]
pub struct BulkUpdateResult {
    pub user_id: String,
    pub success: bool,
    pub message: String,
}

/// Response for bulk update operations
#[derive(Debug, Serialize)]
pub struct BulkUpdateResponse {
    pub total_requested: usize,
    pub successful: usize,
    pub failed: usize,
    pub results: Vec<BulkUpdateResult>,
}

/// User statistics response (admin only)
#[derive(Debug, Serialize)]
pub struct UserStats {
    pub total_users: u64,
    pub active_users: u64,
    pub inactive_users: u64,
    pub admin_users: u64,
    pub regular_users: u64,
}

/// Response for successful authentication
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub success: bool,
    pub message: String,
    pub token: String,
    pub user: UserResponse,
}

/// User profile data returned in API responses
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct UserProfileResponse {
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
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub username: String,
    pub role: Role,
    pub is_active: bool,
    pub profile: UserProfileResponse,
    pub created_at: DateTime<Utc>,
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
#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T: Serialize> {
    pub success: bool,
    pub data: Vec<T>,
    pub total: u64,
    pub page: u64,
    pub per_page: u64,
    pub total_pages: u64,
}
