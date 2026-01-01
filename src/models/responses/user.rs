//! User-related response models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::models::{Role, User, UserProfile};

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

