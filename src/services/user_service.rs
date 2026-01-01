//! User service for user CRUD operations, password management, and admin operations.

use futures::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId};
use mongodb::{Collection, Database};

use log::{debug, info, warn};

use crate::config::CONFIG;
use crate::errors::ApiError;
use crate::models::{
    BulkUpdateResponse, BulkUpdateResult, ChangePasswordRequest, RegisterRequest, Role,
    UpdateUserRequest, User, UserProfile, UserResponse, UserStats,
};
use crate::services::auth_service::{hash_password, verify_password};

pub struct UserService {
    collection: Collection<User>,
}

impl UserService {
    pub fn new(db: &Database) -> Self {
        Self {
            collection: db.collection("users"),
        }
    }

    pub async fn register(&self, req: RegisterRequest) -> Result<User, ApiError> {
        // Check if user already exists
        if self.find_by_email(&req.email).await?.is_some() {
            return Err(ApiError::Conflict("Email already registered".to_string()));
        }

        if self.find_by_username(&req.username).await?.is_some() {
            return Err(ApiError::Conflict("Username already taken".to_string()));
        }

        // Hash password
        let password_hash = hash_password(&req.password)?;

        let now = mongodb::bson::DateTime::now();
        let user = User {
            id: None,
            email: req.email.to_lowercase(),
            username: req.username,
            password_hash,
            role: Role::User, // Default role for new registrations
            is_active: true,
            profile: UserProfile::default(),
            created_at: now,
            updated_at: now,
            last_login: None,
        };

        let result = self.collection.insert_one(&user).await?;
        let id = result.inserted_id.as_object_id().unwrap();

        Ok(User {
            id: Some(id),
            ..user
        })
    }

    pub async fn get_all_users(
        &self,
        page: u64,
        per_page: u64,
        role_filter: Option<&str>,
        active_filter: Option<bool>,
        search_query: Option<&str>,
    ) -> Result<(Vec<UserResponse>, u64), ApiError> {
        // Build filter document
        let mut filter = doc! {};

        if let Some(role) = role_filter {
            filter.insert("role", role.to_lowercase());
        }

        if let Some(is_active) = active_filter {
            filter.insert("is_active", is_active);
        }

        // Add search filter for username, email, first_name, last_name
        if let Some(search) = search_query {
            if !search.trim().is_empty() {
                let search_pattern = regex::escape(search.trim());
                let search_regex = mongodb::bson::Regex {
                    pattern: search_pattern,
                    options: "i".to_string(), // case-insensitive
                };
                filter.insert(
                    "$or",
                    vec![
                        doc! { "username": { "$regex": &search_regex } },
                        doc! { "email": { "$regex": &search_regex } },
                        doc! { "profile.first_name": { "$regex": &search_regex } },
                        doc! { "profile.last_name": { "$regex": &search_regex } },
                    ],
                );
            }
        }

        debug!("Fetching users with filter: {:?}", filter);

        let total = self.collection.count_documents(filter.clone()).await?;
        let skip = (page - 1) * per_page;

        let cursor = self
            .collection
            .find(filter)
            .skip(skip)
            .limit(per_page as i64)
            .sort(doc! { "created_at": -1 })
            .await?;

        let users: Vec<User> = cursor.try_collect().await?;
        let user_responses: Vec<UserResponse> = users.into_iter().map(|u| u.into()).collect();

        Ok((user_responses, total))
    }

    pub async fn get_user_by_id(&self, id: &str) -> Result<Option<User>, ApiError> {
        debug!("Fetching user by ID: {}", id);
        let object_id = ObjectId::parse_str(id)
            .map_err(|_| ApiError::BadRequest("Invalid user ID format".to_string()))?;

        Ok(self.collection.find_one(doc! { "_id": object_id }).await?)
    }

    /// Update user profile (email and/or username)
    pub async fn update_user(
        &self,
        user_id: &str,
        req: UpdateUserRequest,
    ) -> Result<User, ApiError> {
        info!("Updating user profile for user_id: {}", user_id);

        let object_id = ObjectId::parse_str(user_id)
            .map_err(|_| ApiError::BadRequest("Invalid user ID format".to_string()))?;

        // Fetch existing user
        let existing_user = self
            .collection
            .find_one(doc! { "_id": object_id })
            .await?
            .ok_or_else(|| {
                warn!("Update failed: User not found with id: {}", user_id);
                ApiError::NotFound("User not found".to_string())
            })?;

        // Build update document
        let mut update_doc = doc! {};
        let mut has_updates = false;

        // Check and validate email update
        if let Some(ref new_email) = req.email {
            let normalized_email = new_email.to_lowercase();
            if normalized_email != existing_user.email {
                // Check if email is already taken by another user
                if let Some(other_user) = self.find_by_email(&normalized_email).await? {
                    if other_user.id != existing_user.id {
                        warn!(
                            "Update failed: Email {} already taken by another user",
                            normalized_email
                        );
                        return Err(ApiError::Conflict("Email already registered".to_string()));
                    }
                }
                update_doc.insert("email", normalized_email);
                has_updates = true;
            }
        }

        // Check and validate username update
        if let Some(ref new_username) = req.username {
            if *new_username != existing_user.username {
                // Check if username is already taken by another user
                if let Some(other_user) = self.find_by_username(new_username).await? {
                    if other_user.id != existing_user.id {
                        warn!(
                            "Update failed: Username {} already taken by another user",
                            new_username
                        );
                        return Err(ApiError::Conflict("Username already taken".to_string()));
                    }
                }
                update_doc.insert("username", new_username.clone());
                has_updates = true;
            }
        }

        // Update profile fields
        if let Some(ref first_name) = req.first_name {
            update_doc.insert("profile.first_name", first_name.clone());
            has_updates = true;
        }

        if let Some(ref last_name) = req.last_name {
            update_doc.insert("profile.last_name", last_name.clone());
            has_updates = true;
        }

        if let Some(ref phone) = req.phone {
            update_doc.insert("profile.phone", phone.clone());
            has_updates = true;
        }

        if let Some(ref bio) = req.bio {
            update_doc.insert("profile.bio", bio.clone());
            has_updates = true;
        }

        if let Some(ref location) = req.location {
            update_doc.insert("profile.location", location.clone());
            has_updates = true;
        }

        if let Some(ref website) = req.website {
            update_doc.insert("profile.website", website.clone());
            has_updates = true;
        }

        if let Some(ref date_of_birth) = req.date_of_birth {
            update_doc.insert("profile.date_of_birth", date_of_birth.clone());
            has_updates = true;
        }

        if !has_updates {
            debug!("No changes detected for user: {}", user_id);
            return Ok(existing_user);
        }

        // Add updated_at timestamp
        update_doc.insert("updated_at", mongodb::bson::DateTime::now());

        self.collection
            .update_one(doc! { "_id": object_id }, doc! { "$set": update_doc })
            .await?;

        info!("Successfully updated user: {}", user_id);

        // Fetch and return updated user
        self.collection
            .find_one(doc! { "_id": object_id })
            .await?
            .ok_or_else(|| {
                ApiError::InternalServerError("Failed to fetch updated user".to_string())
            })
    }

    /// Delete user by ID
    pub async fn delete_user(&self, user_id: &str) -> Result<(), ApiError> {
        info!("Deleting user with id: {}", user_id);

        let object_id = ObjectId::parse_str(user_id)
            .map_err(|_| ApiError::BadRequest("Invalid user ID format".to_string()))?;

        let result = self
            .collection
            .delete_one(doc! { "_id": object_id })
            .await?;

        if result.deleted_count == 0 {
            warn!("Delete failed: User not found with id: {}", user_id);
            return Err(ApiError::NotFound("User not found".to_string()));
        }

        info!("Successfully deleted user: {}", user_id);
        Ok(())
    }

    /// Change user password
    pub async fn change_password(
        &self,
        user_id: &str,
        req: ChangePasswordRequest,
    ) -> Result<(), ApiError> {
        info!("Changing password for user_id: {}", user_id);

        // Validate new password matches confirmation
        if req.new_password != req.confirm_password {
            warn!(
                "Password change failed: Passwords do not match for user: {}",
                user_id
            );
            return Err(ApiError::BadRequest(
                "New password and confirmation do not match".to_string(),
            ));
        }

        // Prevent using the same password
        if req.current_password == req.new_password {
            warn!(
                "Password change failed: New password same as current for user: {}",
                user_id
            );
            return Err(ApiError::BadRequest(
                "New password must be different from current password".to_string(),
            ));
        }

        let object_id = ObjectId::parse_str(user_id)
            .map_err(|_| ApiError::BadRequest("Invalid user ID format".to_string()))?;

        // Fetch user
        let user = self
            .collection
            .find_one(doc! { "_id": object_id })
            .await?
            .ok_or_else(|| {
                warn!(
                    "Password change failed: User not found with id: {}",
                    user_id
                );
                ApiError::NotFound("User not found".to_string())
            })?;

        // Verify current password
        if !verify_password(&req.current_password, &user.password_hash)? {
            warn!(
                "Password change failed: Invalid current password for user: {}",
                user_id
            );
            return Err(ApiError::Unauthorized(
                "Current password is incorrect".to_string(),
            ));
        }

        // Hash new password
        let new_password_hash = hash_password(&req.new_password)?;

        // Update password
        self.collection
            .update_one(
                doc! { "_id": object_id },
                doc! {
                    "$set": {
                        "password_hash": new_password_hash,
                        "updated_at": mongodb::bson::DateTime::now()
                    }
                },
            )
            .await?;

        info!("Successfully changed password for user: {}", user_id);
        Ok(())
    }

    /// Update user role (admin only operation)
    pub async fn update_role(&self, user_id: &str, new_role: &str) -> Result<User, ApiError> {
        info!(
            "Updating role for user_id: {} to role: {}",
            user_id, new_role
        );

        let object_id = ObjectId::parse_str(user_id)
            .map_err(|_| ApiError::BadRequest("Invalid user ID format".to_string()))?;

        // Parse the role string to Role enum
        let role = Role::from_str(new_role);

        // Fetch existing user to verify they exist
        let existing_user = self
            .collection
            .find_one(doc! { "_id": object_id })
            .await?
            .ok_or_else(|| {
                warn!("Role update failed: User not found with id: {}", user_id);
                ApiError::NotFound("User not found".to_string())
            })?;

        // Check if role is actually changing
        if existing_user.role == role {
            debug!(
                "No role change needed for user {}: already has role {}",
                user_id, new_role
            );
            return Ok(existing_user);
        }

        // Update the role
        self.collection
            .update_one(
                doc! { "_id": object_id },
                doc! {
                    "$set": {
                        "role": role.to_string(),
                        "updated_at": mongodb::bson::DateTime::now()
                    }
                },
            )
            .await?;

        info!(
            "Successfully updated role for user {} from {} to {}",
            user_id, existing_user.role, role
        );

        // Fetch and return updated user
        self.collection
            .find_one(doc! { "_id": object_id })
            .await?
            .ok_or_else(|| {
                ApiError::InternalServerError("Failed to fetch updated user".to_string())
            })
    }

    /// Update user active status (admin only operation)
    pub async fn update_status(&self, user_id: &str, is_active: bool) -> Result<User, ApiError> {
        info!(
            "Updating active status for user_id: {} to: {}",
            user_id, is_active
        );

        let object_id = ObjectId::parse_str(user_id)
            .map_err(|_| ApiError::BadRequest("Invalid user ID format".to_string()))?;

        // Fetch existing user
        let existing_user = self
            .collection
            .find_one(doc! { "_id": object_id })
            .await?
            .ok_or_else(|| {
                warn!("Status update failed: User not found with id: {}", user_id);
                ApiError::NotFound("User not found".to_string())
            })?;

        // Check if status is actually changing
        if existing_user.is_active == is_active {
            debug!(
                "No status change needed for user {}: already {}",
                user_id,
                if is_active { "active" } else { "inactive" }
            );
            return Ok(existing_user);
        }

        // Update the status
        self.collection
            .update_one(
                doc! { "_id": object_id },
                doc! {
                    "$set": {
                        "is_active": is_active,
                        "updated_at": mongodb::bson::DateTime::now()
                    }
                },
            )
            .await?;

        info!(
            "Successfully {} user {}",
            if is_active {
                "activated"
            } else {
                "deactivated"
            },
            user_id
        );

        // Fetch and return updated user
        self.collection
            .find_one(doc! { "_id": object_id })
            .await?
            .ok_or_else(|| {
                ApiError::InternalServerError("Failed to fetch updated user".to_string())
            })
    }

    /// Get user statistics (admin only)
    pub async fn get_stats(&self) -> Result<UserStats, ApiError> {
        info!("Fetching user statistics");

        let total_users = self.collection.count_documents(doc! {}).await?;

        let active_users = self
            .collection
            .count_documents(doc! { "is_active": true })
            .await?;

        let inactive_users = self
            .collection
            .count_documents(doc! { "is_active": false })
            .await?;

        let admin_users = self
            .collection
            .count_documents(doc! { "role": "admin" })
            .await?;

        let regular_users = self
            .collection
            .count_documents(doc! { "role": "user" })
            .await?;

        debug!(
            "User stats: total={}, active={}, inactive={}, admins={}, regular={}",
            total_users, active_users, inactive_users, admin_users, regular_users
        );

        Ok(UserStats {
            total_users,
            active_users,
            inactive_users,
            admin_users,
            regular_users,
        })
    }

    /// Bulk update user status (admin only)
    /// Updates multiple users' active status at once
    /// Returns detailed results for each user
    pub async fn bulk_update_status(
        &self,
        user_ids: &[String],
        is_active: bool,
        admin_user_id: &str,
    ) -> Result<BulkUpdateResponse, ApiError> {
        info!(
            "Bulk updating {} users to is_active={}",
            user_ids.len(),
            is_active
        );

        let mut results: Vec<BulkUpdateResult> = Vec::with_capacity(user_ids.len());
        let mut successful = 0;
        let mut failed = 0;

        for user_id in user_ids {
            // Skip if admin is trying to deactivate themselves
            if user_id == admin_user_id && !is_active {
                results.push(BulkUpdateResult {
                    user_id: user_id.clone(),
                    success: false,
                    message: "Cannot deactivate yourself".to_string(),
                });
                failed += 1;
                continue;
            }

            // Try to update the user
            match self.update_status_internal(user_id, is_active).await {
                Ok(_) => {
                    results.push(BulkUpdateResult {
                        user_id: user_id.clone(),
                        success: true,
                        message: if is_active {
                            "User activated".to_string()
                        } else {
                            "User deactivated".to_string()
                        },
                    });
                    successful += 1;
                }
                Err(e) => {
                    results.push(BulkUpdateResult {
                        user_id: user_id.clone(),
                        success: false,
                        message: e.to_string(),
                    });
                    failed += 1;
                }
            }
        }

        info!(
            "Bulk update complete: {} successful, {} failed",
            successful, failed
        );

        Ok(BulkUpdateResponse {
            total_requested: user_ids.len(),
            successful,
            failed,
            results,
        })
    }

    /// Internal helper for updating user status (no self-deactivation check)
    async fn update_status_internal(&self, user_id: &str, is_active: bool) -> Result<(), ApiError> {
        let object_id = ObjectId::parse_str(user_id)
            .map_err(|_| ApiError::BadRequest("Invalid user ID format".to_string()))?;

        let result = self
            .collection
            .update_one(
                doc! { "_id": object_id },
                doc! {
                    "$set": {
                        "is_active": is_active,
                        "updated_at": mongodb::bson::DateTime::now()
                    }
                },
            )
            .await?;

        if result.matched_count == 0 {
            return Err(ApiError::NotFound("User not found".to_string()));
        }

        Ok(())
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, ApiError> {
        Ok(self
            .collection
            .find_one(doc! { "email": email.to_lowercase() })
            .await?)
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>, ApiError> {
        Ok(self
            .collection
            .find_one(doc! { "username": username })
            .await?)
    }

    /// Seed the database with an initial admin user if no admin exists
    /// This is called on application startup when SEED_ADMIN is true
    pub async fn seed_admin(&self) -> Result<(), ApiError> {
        if !CONFIG.seed_admin {
            info!("Admin seeding is disabled (SEED_ADMIN=false)");
            return Ok(());
        }

        // Check if any admin user already exists
        let admin_exists = self
            .collection
            .find_one(doc! { "role": "Admin" })
            .await?
            .is_some();

        if admin_exists {
            info!("Admin user already exists, skipping seed");
            return Ok(());
        }

        // Check if the configured admin email or username already exists
        if self.find_by_email(&CONFIG.admin_email).await?.is_some() {
            warn!(
                "User with email {} already exists but is not an admin",
                CONFIG.admin_email
            );
            return Ok(());
        }

        if self
            .find_by_username(&CONFIG.admin_username)
            .await?
            .is_some()
        {
            warn!(
                "User with username {} already exists but is not an admin",
                CONFIG.admin_username
            );
            return Ok(());
        }

        // Create the admin user
        let password_hash = hash_password(&CONFIG.admin_password)?;
        let now = mongodb::bson::DateTime::now();

        let admin_user = User {
            id: None,
            email: CONFIG.admin_email.to_lowercase(),
            username: CONFIG.admin_username.clone(),
            password_hash,
            role: Role::Admin,
            is_active: true,
            profile: UserProfile {
                first_name: Some("System".to_string()),
                last_name: Some("Administrator".to_string()),
                ..Default::default()
            },
            created_at: now,
            updated_at: now,
            last_login: None,
        };

        self.collection.insert_one(&admin_user).await?;

        info!(
            "✅ Admin user created successfully: {} ({})",
            CONFIG.admin_username, CONFIG.admin_email
        );
        info!("⚠️  Please change the default admin password after first login!");

        Ok(())
    }
}
