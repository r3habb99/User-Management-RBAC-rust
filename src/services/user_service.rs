use bcrypt::{hash, verify, DEFAULT_COST};
use bson::{doc, oid::ObjectId};
use chrono::Utc;
use futures::TryStreamExt;
use jsonwebtoken::{encode, EncodingKey, Header};
use mongodb::{Collection, Database};

use log::{debug, info, warn};

use crate::config::CONFIG;
use crate::errors::ApiError;
use crate::models::{
    BulkUpdateResponse, BulkUpdateResult, ChangePasswordRequest, Claims, LoginRequest,
    RegisterRequest, Role, UpdateUserRequest, User, UserResponse, UserStats,
};

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
        let password_hash = hash(&req.password, DEFAULT_COST)?;

        let now = bson::DateTime::now();
        let user = User {
            id: None,
            email: req.email.to_lowercase(),
            username: req.username,
            password_hash,
            role: Role::User, // Default role for new registrations
            is_active: true,
            created_at: now,
            updated_at: now,
            last_login: None,
        };

        let result = self.collection.insert_one(&user, None).await?;
        let id = result.inserted_id.as_object_id().unwrap();

        Ok(User {
            id: Some(id),
            ..user
        })
    }

    pub async fn login(&self, req: LoginRequest) -> Result<(User, String), ApiError> {
        let user = self
            .find_by_email(&req.email)
            .await?
            .ok_or_else(|| ApiError::Unauthorized("Invalid email or password".to_string()))?;

        if !user.is_active {
            return Err(ApiError::Unauthorized("Account is deactivated".to_string()));
        }

        // Verify password
        if !verify(&req.password, &user.password_hash)? {
            return Err(ApiError::Unauthorized(
                "Invalid email or password".to_string(),
            ));
        }

        // Update last login
        let user_id = user.id.unwrap();
        self.collection
            .update_one(
                doc! { "_id": user_id },
                doc! { "$set": { "last_login": Utc::now() } },
                None,
            )
            .await?;

        // Generate JWT token
        let token = self.generate_token(&user)?;

        Ok((user, token))
    }

    pub async fn get_all_users(
        &self,
        page: u64,
        per_page: u64,
        role_filter: Option<&str>,
        active_filter: Option<bool>,
    ) -> Result<(Vec<UserResponse>, u64), ApiError> {
        // Build filter document
        let mut filter = doc! {};

        if let Some(role) = role_filter {
            filter.insert("role", role.to_lowercase());
        }

        if let Some(is_active) = active_filter {
            filter.insert("is_active", is_active);
        }

        debug!("Fetching users with filter: {:?}", filter);

        let total = self
            .collection
            .count_documents(filter.clone(), None)
            .await?;
        let skip = (page - 1) * per_page;

        let cursor = self
            .collection
            .find(
                filter,
                mongodb::options::FindOptions::builder()
                    .skip(skip)
                    .limit(per_page as i64)
                    .sort(doc! { "created_at": -1 })
                    .build(),
            )
            .await?;

        let users: Vec<User> = cursor.try_collect().await?;
        let user_responses: Vec<UserResponse> = users.into_iter().map(|u| u.into()).collect();

        Ok((user_responses, total))
    }

    pub async fn get_user_by_id(&self, id: &str) -> Result<Option<User>, ApiError> {
        debug!("Fetching user by ID: {}", id);
        let object_id = ObjectId::parse_str(id)
            .map_err(|_| ApiError::BadRequest("Invalid user ID format".to_string()))?;

        Ok(self
            .collection
            .find_one(doc! { "_id": object_id }, None)
            .await?)
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
            .find_one(doc! { "_id": object_id }, None)
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

        if !has_updates {
            debug!("No changes detected for user: {}", user_id);
            return Ok(existing_user);
        }

        // Add updated_at timestamp
        update_doc.insert("updated_at", bson::DateTime::now());

        self.collection
            .update_one(doc! { "_id": object_id }, doc! { "$set": update_doc }, None)
            .await?;

        info!("Successfully updated user: {}", user_id);

        // Fetch and return updated user
        self.collection
            .find_one(doc! { "_id": object_id }, None)
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
            .delete_one(doc! { "_id": object_id }, None)
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
            .find_one(doc! { "_id": object_id }, None)
            .await?
            .ok_or_else(|| {
                warn!(
                    "Password change failed: User not found with id: {}",
                    user_id
                );
                ApiError::NotFound("User not found".to_string())
            })?;

        // Verify current password
        if !verify(&req.current_password, &user.password_hash)? {
            warn!(
                "Password change failed: Invalid current password for user: {}",
                user_id
            );
            return Err(ApiError::Unauthorized(
                "Current password is incorrect".to_string(),
            ));
        }

        // Hash new password
        let new_password_hash = hash(&req.new_password, DEFAULT_COST)?;

        // Update password
        self.collection
            .update_one(
                doc! { "_id": object_id },
                doc! {
                    "$set": {
                        "password_hash": new_password_hash,
                        "updated_at": bson::DateTime::now()
                    }
                },
                None,
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
            .find_one(doc! { "_id": object_id }, None)
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
                        "updated_at": bson::DateTime::now()
                    }
                },
                None,
            )
            .await?;

        info!(
            "Successfully updated role for user {} from {} to {}",
            user_id, existing_user.role, role
        );

        // Fetch and return updated user
        self.collection
            .find_one(doc! { "_id": object_id }, None)
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
            .find_one(doc! { "_id": object_id }, None)
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
                        "updated_at": bson::DateTime::now()
                    }
                },
                None,
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
            .find_one(doc! { "_id": object_id }, None)
            .await?
            .ok_or_else(|| {
                ApiError::InternalServerError("Failed to fetch updated user".to_string())
            })
    }

    /// Get user statistics (admin only)
    pub async fn get_stats(&self) -> Result<UserStats, ApiError> {
        info!("Fetching user statistics");

        let total_users = self.collection.count_documents(doc! {}, None).await?;

        let active_users = self
            .collection
            .count_documents(doc! { "is_active": true }, None)
            .await?;

        let inactive_users = self
            .collection
            .count_documents(doc! { "is_active": false }, None)
            .await?;

        let admin_users = self
            .collection
            .count_documents(doc! { "role": "admin" }, None)
            .await?;

        let regular_users = self
            .collection
            .count_documents(doc! { "role": "user" }, None)
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
                        "updated_at": bson::DateTime::now()
                    }
                },
                None,
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
            .find_one(doc! { "email": email.to_lowercase() }, None)
            .await?)
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>, ApiError> {
        Ok(self
            .collection
            .find_one(doc! { "username": username }, None)
            .await?)
    }

    fn generate_token(&self, user: &User) -> Result<String, ApiError> {
        let now = Utc::now().timestamp() as usize;
        let exp = now + (CONFIG.jwt_expiration_hours as usize * 3600);

        let claims = Claims {
            sub: user.id.unwrap().to_hex(),
            email: user.email.clone(),
            role: user.role.to_string(),
            exp,
            iat: now,
        };

        debug!(
            "Generated token for user {} with role {}",
            user.email, user.role
        );

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(CONFIG.jwt_secret.as_bytes()),
        )?;

        Ok(token)
    }
}
