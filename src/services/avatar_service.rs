//! Avatar service for updating and deleting user avatars.

use log::{info, warn};
use mongodb::bson::oid::ObjectId;
use mongodb::Database;
use std::sync::Arc;

use crate::errors::ApiError;
use crate::models::{User, UserProfile};
use crate::repositories::UserRepository;

/// Service for avatar operations.
pub struct AvatarService {
    repository: Arc<UserRepository>,
}

impl AvatarService {
    /// Create a new AvatarService instance.
    pub fn new(db: &Database) -> Self {
        Self {
            repository: Arc::new(UserRepository::new(db)),
        }
    }

    /// Create a new AvatarService with a shared repository (for dependency injection).
    #[allow(dead_code)]
    pub fn with_repository(repository: Arc<UserRepository>) -> Self {
        Self { repository }
    }

    /// Update user avatar URL.
    pub async fn update_avatar(&self, user_id: &str, avatar_url: &str) -> Result<User, ApiError> {
        info!("Updating avatar for user_id: {}", user_id);

        let object_id = ObjectId::parse_str(user_id)
            .map_err(|_| ApiError::BadRequest("Invalid user ID format".to_string()))?;

        // Verify user exists
        let existing = self
            .repository
            .find_by_id(object_id)
            .await?
            .ok_or_else(|| {
                warn!("Avatar update failed: User not found with id: {}", user_id);
                ApiError::NotFound("User not found".to_string())
            })?;

        self.repository.update_avatar(object_id, avatar_url).await?;

        info!("Successfully updated avatar for user: {}", user_id);

        // Return updated user
        Ok(User {
            profile: UserProfile {
                avatar_url: Some(avatar_url.to_string()),
                ..existing.profile
            },
            updated_at: mongodb::bson::DateTime::now(),
            ..existing
        })
    }

    /// Delete user avatar.
    pub async fn delete_avatar(&self, user_id: &str) -> Result<User, ApiError> {
        info!("Deleting avatar for user_id: {}", user_id);

        let object_id = ObjectId::parse_str(user_id)
            .map_err(|_| ApiError::BadRequest("Invalid user ID format".to_string()))?;

        // Verify user exists
        let existing = self
            .repository
            .find_by_id(object_id)
            .await?
            .ok_or_else(|| {
                warn!("Avatar delete failed: User not found with id: {}", user_id);
                ApiError::NotFound("User not found".to_string())
            })?;

        self.repository.delete_avatar(object_id).await?;

        info!("Successfully deleted avatar for user: {}", user_id);

        // Return updated user
        Ok(User {
            profile: UserProfile {
                avatar_url: None,
                ..existing.profile
            },
            updated_at: mongodb::bson::DateTime::now(),
            ..existing
        })
    }

    /// Get user by ID (for avatar operations that need user data).
    pub async fn get_user_by_id(&self, id: &str) -> Result<Option<User>, ApiError> {
        let object_id = ObjectId::parse_str(id)
            .map_err(|_| ApiError::BadRequest("Invalid user ID format".to_string()))?;

        self.repository.find_by_id(object_id).await
    }
}
