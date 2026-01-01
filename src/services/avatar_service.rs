//! Avatar service for updating and deleting user avatars.

use log::{info, warn};
use mongodb::bson::{doc, oid::ObjectId};
use mongodb::{Collection, Database};

use crate::errors::ApiError;
use crate::models::{User, UserProfile};

/// Service for avatar operations.
pub struct AvatarService {
    collection: Collection<User>,
}

impl AvatarService {
    /// Create a new AvatarService instance.
    pub fn new(db: &Database) -> Self {
        Self {
            collection: db.collection("users"),
        }
    }

    /// Update user avatar URL.
    pub async fn update_avatar(&self, user_id: &str, avatar_url: &str) -> Result<User, ApiError> {
        info!("Updating avatar for user_id: {}", user_id);

        let object_id = ObjectId::parse_str(user_id)
            .map_err(|_| ApiError::BadRequest("Invalid user ID format".to_string()))?;

        // Verify user exists
        let existing = self
            .collection
            .find_one(doc! { "_id": object_id })
            .await?
            .ok_or_else(|| {
                warn!("Avatar update failed: User not found with id: {}", user_id);
                ApiError::NotFound("User not found".to_string())
            })?;

        self.collection
            .update_one(
                doc! { "_id": object_id },
                doc! {
                    "$set": {
                        "profile.avatar_url": avatar_url,
                        "updated_at": mongodb::bson::DateTime::now()
                    }
                },
            )
            .await?;

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
            .collection
            .find_one(doc! { "_id": object_id })
            .await?
            .ok_or_else(|| {
                warn!("Avatar delete failed: User not found with id: {}", user_id);
                ApiError::NotFound("User not found".to_string())
            })?;

        self.collection
            .update_one(
                doc! { "_id": object_id },
                doc! {
                    "$unset": { "profile.avatar_url": "" },
                    "$set": { "updated_at": mongodb::bson::DateTime::now() }
                },
            )
            .await?;

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

        Ok(self.collection.find_one(doc! { "_id": object_id }).await?)
    }
}

