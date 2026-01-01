//! User repository for all MongoDB operations related to users.
//!
//! This repository encapsulates all database access logic for the User collection,
//! providing a clean interface for the service layer.

use futures::TryStreamExt;
use log::{debug, info};
use mongodb::bson::{doc, oid::ObjectId, Document};
use mongodb::{Collection, Database, IndexModel};

use crate::constants::COLLECTION_USERS;
use crate::errors::ApiError;
use crate::models::User;

/// Repository for user-related database operations.
pub struct UserRepository {
    collection: Collection<User>,
}

impl UserRepository {
    /// Create a new UserRepository instance.
    pub fn new(db: &Database) -> Self {
        Self {
            collection: db.collection(COLLECTION_USERS),
        }
    }

    /// Create database indexes for commonly queried fields.
    ///
    /// This method should be called once during application startup to ensure
    /// optimal query performance. It creates the following indexes:
    /// - Unique index on `email`
    /// - Unique index on `username`
    /// - Compound index on `role` and `is_active`
    pub async fn create_indexes(&self) -> Result<(), ApiError> {
        info!("Creating database indexes for users collection...");

        let indexes = vec![
            // Unique index on email
            IndexModel::builder()
                .keys(doc! { "email": 1 })
                .options(
                    mongodb::options::IndexOptions::builder()
                        .unique(true)
                        .build(),
                )
                .build(),
            // Unique index on username
            IndexModel::builder()
                .keys(doc! { "username": 1 })
                .options(
                    mongodb::options::IndexOptions::builder()
                        .unique(true)
                        .build(),
                )
                .build(),
            // Compound index on role and is_active for filtering queries
            IndexModel::builder()
                .keys(doc! { "role": 1, "is_active": 1 })
                .build(),
        ];

        self.collection.create_indexes(indexes).await?;
        info!("Database indexes created successfully");
        Ok(())
    }

    /// Insert a new user into the database.
    pub async fn insert(&self, user: &User) -> Result<ObjectId, ApiError> {
        let result = self.collection.insert_one(user).await?;
        Ok(result.inserted_id.as_object_id().unwrap())
    }

    /// Find a user by their ObjectId.
    pub async fn find_by_id(&self, id: ObjectId) -> Result<Option<User>, ApiError> {
        debug!("Repository: Finding user by ID: {}", id);
        Ok(self.collection.find_one(doc! { "_id": id }).await?)
    }

    /// Find a user by email address (case-insensitive).
    pub async fn find_by_email(&self, email: &str) -> Result<Option<User>, ApiError> {
        debug!("Repository: Finding user by email: {}", email);
        Ok(self
            .collection
            .find_one(doc! { "email": email.to_lowercase() })
            .await?)
    }

    /// Find a user by username.
    pub async fn find_by_username(&self, username: &str) -> Result<Option<User>, ApiError> {
        debug!("Repository: Finding user by username: {}", username);
        Ok(self
            .collection
            .find_one(doc! { "username": username })
            .await?)
    }

    /// Find a user by role.
    pub async fn find_by_role(&self, role: &str) -> Result<Option<User>, ApiError> {
        debug!("Repository: Finding user by role: {}", role);
        Ok(self.collection.find_one(doc! { "role": role }).await?)
    }

    /// Find users with pagination and filtering.
    pub async fn find_with_filter(
        &self,
        filter: Document,
        skip: u64,
        limit: i64,
    ) -> Result<Vec<User>, ApiError> {
        debug!("Repository: Finding users with filter: {:?}", filter);
        let cursor = self
            .collection
            .find(filter)
            .skip(skip)
            .limit(limit)
            .sort(doc! { "created_at": -1 })
            .await?;

        Ok(cursor.try_collect().await?)
    }

    /// Count documents matching a filter.
    pub async fn count(&self, filter: Document) -> Result<u64, ApiError> {
        Ok(self.collection.count_documents(filter).await?)
    }

    /// Update a user document.
    pub async fn update(
        &self,
        id: ObjectId,
        update: Document,
    ) -> Result<mongodb::results::UpdateResult, ApiError> {
        Ok(self
            .collection
            .update_one(doc! { "_id": id }, doc! { "$set": update })
            .await?)
    }

    /// Delete a user by ObjectId.
    pub async fn delete(&self, id: ObjectId) -> Result<mongodb::results::DeleteResult, ApiError> {
        Ok(self.collection.delete_one(doc! { "_id": id }).await?)
    }

    /// Update last login timestamp for a user.
    pub async fn update_last_login(&self, id: ObjectId) -> Result<(), ApiError> {
        self.collection
            .update_one(
                doc! { "_id": id },
                doc! { "$set": { "last_login": mongodb::bson::DateTime::now() } },
            )
            .await?;
        Ok(())
    }

    /// Update user password.
    pub async fn update_password(&self, id: ObjectId, password_hash: &str) -> Result<(), ApiError> {
        self.collection
            .update_one(
                doc! { "_id": id },
                doc! {
                    "$set": {
                        "password_hash": password_hash,
                        "updated_at": mongodb::bson::DateTime::now()
                    }
                },
            )
            .await?;
        Ok(())
    }

    /// Update user role.
    pub async fn update_role(&self, id: ObjectId, role: &str) -> Result<(), ApiError> {
        self.collection
            .update_one(
                doc! { "_id": id },
                doc! {
                    "$set": {
                        "role": role,
                        "updated_at": mongodb::bson::DateTime::now()
                    }
                },
            )
            .await?;
        Ok(())
    }

    /// Update user active status.
    pub async fn update_status(
        &self,
        id: ObjectId,
        is_active: bool,
    ) -> Result<mongodb::results::UpdateResult, ApiError> {
        Ok(self
            .collection
            .update_one(
                doc! { "_id": id },
                doc! {
                    "$set": {
                        "is_active": is_active,
                        "updated_at": mongodb::bson::DateTime::now()
                    }
                },
            )
            .await?)
    }

    /// Update user avatar URL.
    pub async fn update_avatar(&self, id: ObjectId, avatar_url: &str) -> Result<(), ApiError> {
        debug!("Repository: Updating avatar for user: {}", id);
        self.collection
            .update_one(
                doc! { "_id": id },
                doc! {
                    "$set": {
                        "profile.avatar_url": avatar_url,
                        "updated_at": mongodb::bson::DateTime::now()
                    }
                },
            )
            .await?;
        Ok(())
    }

    /// Delete user avatar (set to null).
    pub async fn delete_avatar(&self, id: ObjectId) -> Result<(), ApiError> {
        debug!("Repository: Deleting avatar for user: {}", id);
        self.collection
            .update_one(
                doc! { "_id": id },
                doc! {
                    "$unset": { "profile.avatar_url": "" },
                    "$set": { "updated_at": mongodb::bson::DateTime::now() }
                },
            )
            .await?;
        Ok(())
    }
}
