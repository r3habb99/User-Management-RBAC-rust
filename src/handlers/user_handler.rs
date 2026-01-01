use actix_multipart::Multipart;
use actix_web::{web, HttpRequest, HttpResponse};
use futures::StreamExt;
use log::{debug, info, warn};
use std::io::Write;
use std::path::Path;
use uuid::Uuid;
use validator::Validate;

use crate::config::CONFIG;
use crate::errors::ApiError;
use crate::middleware::RequestExt;
use crate::models::{
    ApiResponse, AuthResponse, BulkUpdateStatusRequest, ChangePasswordRequest, LoginRequest,
    PaginatedResponse, RegisterRequest, UpdateRoleRequest, UpdateStatusRequest, UpdateUserRequest,
    UserResponse, UserStats,
};
use crate::services::UserService;

/// POST /api/auth/register
pub async fn register(
    user_service: web::Data<UserService>,
    body: web::Json<RegisterRequest>,
) -> Result<HttpResponse, ApiError> {
    // Validate input
    body.validate().map_err(|e| {
        let errors: Vec<String> = e
            .field_errors()
            .iter()
            .flat_map(|(_, errs)| {
                errs.iter()
                    .map(|e| e.message.clone().unwrap_or_default().to_string())
            })
            .collect();
        ApiError::ValidationError(errors)
    })?;

    let user = user_service.register(body.into_inner()).await?;
    let user_response: UserResponse = user.into();

    Ok(HttpResponse::Created().json(ApiResponse::success(
        "User registered successfully",
        user_response,
    )))
}

/// POST /api/auth/login
pub async fn login(
    user_service: web::Data<UserService>,
    body: web::Json<LoginRequest>,
) -> Result<HttpResponse, ApiError> {
    // Validate input
    body.validate().map_err(|e| {
        let errors: Vec<String> = e
            .field_errors()
            .iter()
            .flat_map(|(_, errs)| {
                errs.iter()
                    .map(|e| e.message.clone().unwrap_or_default().to_string())
            })
            .collect();
        ApiError::ValidationError(errors)
    })?;

    let (user, token) = user_service.login(body.into_inner()).await?;

    Ok(HttpResponse::Ok().json(AuthResponse {
        success: true,
        message: "Login successful".to_string(),
        token,
        user: user.into(),
    }))
}

/// POST /api/auth/logout
pub async fn logout() -> Result<HttpResponse, ApiError> {
    // For JWT-based auth, logout is typically handled client-side by removing the token
    // Server-side, you might want to implement a token blacklist for additional security
    Ok(HttpResponse::Ok().json(ApiResponse::<()>::message("Logout successful")))
}

/// GET /api/users
/// Supports pagination, optional filters (role, is_active), and search query
pub async fn get_users(
    user_service: web::Data<UserService>,
    query: web::Query<UserListQuery>,
) -> Result<HttpResponse, ApiError> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(10).min(100);

    let (users, total) = user_service
        .get_all_users(
            page,
            per_page,
            query.role.as_deref(),
            query.is_active,
            query.search.as_deref(),
        )
        .await?;
    let total_pages = (total as f64 / per_page as f64).ceil() as u64;

    Ok(HttpResponse::Ok().json(PaginatedResponse {
        success: true,
        data: users,
        total,
        page,
        per_page,
        total_pages,
    }))
}

/// GET /api/users/{id}
pub async fn get_user(
    user_service: web::Data<UserService>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let user_id = path.into_inner();
    debug!("Fetching user with id: {}", user_id);

    let user = user_service
        .get_user_by_id(&user_id)
        .await?
        .ok_or_else(|| {
            warn!("User not found with id: {}", user_id);
            ApiError::NotFound("User not found".to_string())
        })?;

    let user_response: UserResponse = user.into();
    info!("Successfully fetched user: {}", user_id);
    Ok(HttpResponse::Ok().json(ApiResponse::success("User found", user_response)))
}

/// GET /api/users/me - Get current authenticated user
pub async fn get_current_user(
    user_service: web::Data<UserService>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let claims = req.get_claims().ok_or_else(|| {
        warn!("Failed to get claims from request");
        ApiError::Unauthorized("Authentication required".to_string())
    })?;

    debug!("Fetching current user with id: {}", claims.sub);

    let user = user_service
        .get_user_by_id(&claims.sub)
        .await?
        .ok_or_else(|| {
            warn!("Current user not found with id: {}", claims.sub);
            ApiError::NotFound("User not found".to_string())
        })?;

    let user_response: UserResponse = user.into();
    info!("Successfully fetched current user: {}", claims.sub);
    Ok(HttpResponse::Ok().json(ApiResponse::success(
        "User profile retrieved",
        user_response,
    )))
}

/// PUT /api/users/{id} - Update user profile
/// Admins can update any user, regular users can only update themselves
pub async fn update_user(
    user_service: web::Data<UserService>,
    path: web::Path<String>,
    body: web::Json<UpdateUserRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let user_id = path.into_inner();

    // Get current user from JWT claims
    let claims = req.get_claims().ok_or_else(|| {
        warn!("Failed to get claims from request for update");
        ApiError::Unauthorized("Authentication required".to_string())
    })?;

    // Check authorization: user can update their own profile, or admin can update any user
    if !claims.can_access(&user_id) {
        warn!(
            "User {} (role: {}) attempted to update profile of user {}",
            claims.sub, claims.role, user_id
        );
        return Err(ApiError::Unauthorized(
            "You don't have permission to update this user's profile".to_string(),
        ));
    }

    // Log if admin is updating another user
    if claims.is_admin() && claims.sub != user_id {
        info!("Admin {} updating profile of user {}", claims.sub, user_id);
    }

    // Validate input
    body.validate().map_err(|e| {
        let errors: Vec<String> = e
            .field_errors()
            .iter()
            .flat_map(|(_, errs)| {
                errs.iter()
                    .map(|e| e.message.clone().unwrap_or_default().to_string())
            })
            .collect();
        warn!("Validation failed for update user: {:?}", errors);
        ApiError::ValidationError(errors)
    })?;

    info!("Updating user profile for user_id: {}", user_id);
    let updated_user = user_service
        .update_user(&user_id, body.into_inner())
        .await?;
    let user_response: UserResponse = updated_user.into();

    info!("Successfully updated user: {}", user_id);
    Ok(HttpResponse::Ok().json(ApiResponse::success(
        "User profile updated successfully",
        user_response,
    )))
}

/// DELETE /api/users/{id} - Delete user account
/// Admins can delete any user, regular users can only delete themselves
pub async fn delete_user(
    user_service: web::Data<UserService>,
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let user_id = path.into_inner();

    // Get current user from JWT claims
    let claims = req.get_claims().ok_or_else(|| {
        warn!("Failed to get claims from request for delete");
        ApiError::Unauthorized("Authentication required".to_string())
    })?;

    // Check authorization: user can delete their own account, or admin can delete any user
    if !claims.can_access(&user_id) {
        warn!(
            "User {} (role: {}) attempted to delete account of user {}",
            claims.sub, claims.role, user_id
        );
        return Err(ApiError::Unauthorized(
            "You don't have permission to delete this user's account".to_string(),
        ));
    }

    // Log if admin is deleting another user
    if claims.is_admin() && claims.sub != user_id {
        info!("Admin {} deleting account of user {}", claims.sub, user_id);
    }

    info!("Deleting user account for user_id: {}", user_id);
    user_service.delete_user(&user_id).await?;

    info!("Successfully deleted user: {}", user_id);
    Ok(HttpResponse::Ok().json(ApiResponse::<()>::message(
        "User account deleted successfully",
    )))
}

/// PATCH /api/users/{id}/password - Change user password
/// Note: Password changes require current password verification, so even admins
/// can only change their own password. For admin password resets, use a separate
/// admin reset endpoint (not implemented - would send reset email).
pub async fn change_password(
    user_service: web::Data<UserService>,
    path: web::Path<String>,
    body: web::Json<ChangePasswordRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let user_id = path.into_inner();

    // Get current user from JWT claims
    let claims = req.get_claims().ok_or_else(|| {
        warn!("Failed to get claims from request for password change");
        ApiError::Unauthorized("Authentication required".to_string())
    })?;

    // Password changes always require knowing the current password,
    // so users (including admins) can only change their own password
    if claims.sub != user_id {
        warn!(
            "User {} (role: {}) attempted to change password of user {}",
            claims.sub, claims.role, user_id
        );
        return Err(ApiError::Unauthorized(
            "You can only change your own password. For other users, use the password reset feature.".to_string(),
        ));
    }

    // Validate input
    body.validate().map_err(|e| {
        let errors: Vec<String> = e
            .field_errors()
            .iter()
            .flat_map(|(_, errs)| {
                errs.iter()
                    .map(|e| e.message.clone().unwrap_or_default().to_string())
            })
            .collect();
        warn!("Validation failed for change password: {:?}", errors);
        ApiError::ValidationError(errors)
    })?;

    info!("Changing password for user_id: {}", user_id);
    user_service
        .change_password(&user_id, body.into_inner())
        .await?;

    info!("Successfully changed password for user: {}", user_id);
    Ok(HttpResponse::Ok().json(ApiResponse::<()>::message("Password changed successfully")))
}

/// PATCH /api/users/{id}/role - Update user role (admin only)
/// Only admins can promote or demote users
pub async fn update_role(
    user_service: web::Data<UserService>,
    path: web::Path<String>,
    body: web::Json<UpdateRoleRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let user_id = path.into_inner();

    // Get current user from JWT claims
    let claims = req.get_claims().ok_or_else(|| {
        warn!("Failed to get claims from request for role update");
        ApiError::Unauthorized("Authentication required".to_string())
    })?;

    // Only admins can update roles
    if !claims.is_admin() {
        warn!(
            "Non-admin user {} attempted to update role of user {}",
            claims.sub, user_id
        );
        return Err(ApiError::Unauthorized(
            "Only administrators can update user roles".to_string(),
        ));
    }

    // Prevent admin from demoting themselves
    if claims.sub == user_id && body.role.to_lowercase() != "admin" {
        warn!("Admin {} attempted to demote themselves", claims.sub);
        return Err(ApiError::BadRequest(
            "Administrators cannot demote themselves. Ask another admin to do this.".to_string(),
        ));
    }

    // Validate input
    body.validate().map_err(|e| {
        let errors: Vec<String> = e
            .field_errors()
            .iter()
            .flat_map(|(_, errs)| {
                errs.iter()
                    .map(|e| e.message.clone().unwrap_or_default().to_string())
            })
            .collect();
        warn!("Validation failed for update role: {:?}", errors);
        ApiError::ValidationError(errors)
    })?;

    info!(
        "Admin {} updating role of user {} to {}",
        claims.sub, user_id, body.role
    );

    let updated_user = user_service.update_role(&user_id, &body.role).await?;
    let user_response: UserResponse = updated_user.into();

    info!(
        "Successfully updated role for user {} to {}",
        user_id, body.role
    );
    Ok(HttpResponse::Ok().json(ApiResponse::success(
        "User role updated successfully",
        user_response,
    )))
}

/// Query parameters for listing users with pagination, filters, and search
#[derive(Debug, serde::Deserialize)]
pub struct UserListQuery {
    pub page: Option<u64>,
    pub per_page: Option<u64>,
    /// Filter by role: "admin" or "user"
    pub role: Option<String>,
    /// Filter by active status: true or false
    pub is_active: Option<bool>,
    /// Search query to filter by username, email, first_name, or last_name
    pub search: Option<String>,
}

/// PATCH /api/users/{id}/status - Update user active status (admin only)
pub async fn update_status(
    user_service: web::Data<UserService>,
    path: web::Path<String>,
    body: web::Json<UpdateStatusRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let user_id = path.into_inner();

    // Get current user from JWT claims
    let claims = req.get_claims().ok_or_else(|| {
        warn!("Failed to get claims from request for status update");
        ApiError::Unauthorized("Authentication required".to_string())
    })?;

    // Only admins can update user status
    if !claims.is_admin() {
        warn!(
            "Non-admin user {} attempted to update status of user {}",
            claims.sub, user_id
        );
        return Err(ApiError::Unauthorized(
            "Only administrators can update user status".to_string(),
        ));
    }

    // Prevent admin from deactivating themselves
    if claims.sub == user_id && !body.is_active {
        warn!("Admin {} attempted to deactivate themselves", claims.sub);
        return Err(ApiError::BadRequest(
            "Administrators cannot deactivate themselves".to_string(),
        ));
    }

    info!(
        "Admin {} {} user {}",
        claims.sub,
        if body.is_active {
            "activating"
        } else {
            "deactivating"
        },
        user_id
    );

    let updated_user = user_service.update_status(&user_id, body.is_active).await?;
    let user_response: UserResponse = updated_user.into();

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        if body.is_active {
            "User activated successfully"
        } else {
            "User deactivated successfully"
        },
        user_response,
    )))
}

/// GET /api/admin/stats - Get user statistics (admin only)
pub async fn get_user_stats(
    user_service: web::Data<UserService>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    // Get current user from JWT claims
    let claims = req.get_claims().ok_or_else(|| {
        warn!("Failed to get claims from request for stats");
        ApiError::Unauthorized("Authentication required".to_string())
    })?;

    // Only admins can view statistics
    if !claims.is_admin() {
        warn!(
            "Non-admin user {} attempted to access user statistics",
            claims.sub
        );
        return Err(ApiError::Unauthorized(
            "Only administrators can view user statistics".to_string(),
        ));
    }

    info!("Admin {} fetching user statistics", claims.sub);

    let stats: UserStats = user_service.get_stats().await?;

    Ok(HttpResponse::Ok().json(ApiResponse::success("User statistics", stats)))
}

/// PATCH /api/admin/users/bulk-status - Bulk update user status (admin only)
/// Activate or deactivate multiple users at once
pub async fn bulk_update_status(
    user_service: web::Data<UserService>,
    body: web::Json<BulkUpdateStatusRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    // Get current user from JWT claims
    let claims = req.get_claims().ok_or_else(|| {
        warn!("Failed to get claims from request for bulk status update");
        ApiError::Unauthorized("Authentication required".to_string())
    })?;

    // Only admins can perform bulk operations
    if !claims.is_admin() {
        warn!("Non-admin user {} attempted bulk status update", claims.sub);
        return Err(ApiError::Unauthorized(
            "Only administrators can perform bulk operations".to_string(),
        ));
    }

    // Validate that we have at least one user ID
    if body.user_ids.is_empty() {
        return Err(ApiError::BadRequest(
            "At least one user ID is required".to_string(),
        ));
    }

    // Limit bulk operations to prevent abuse
    const MAX_BULK_SIZE: usize = 100;
    if body.user_ids.len() > MAX_BULK_SIZE {
        return Err(ApiError::BadRequest(format!(
            "Maximum {} users can be updated at once",
            MAX_BULK_SIZE
        )));
    }

    info!(
        "Admin {} performing bulk {} on {} users",
        claims.sub,
        if body.is_active {
            "activation"
        } else {
            "deactivation"
        },
        body.user_ids.len()
    );

    let response = user_service
        .bulk_update_status(&body.user_ids, body.is_active, &claims.sub)
        .await?;

    let message = format!(
        "Bulk update complete: {} successful, {} failed",
        response.successful, response.failed
    );

    Ok(HttpResponse::Ok().json(ApiResponse::success(&message, response)))
}

/// POST /api/users/{id}/avatar - Upload user avatar
/// Users can upload their own avatar, admins can upload for any user
pub async fn upload_avatar(
    user_service: web::Data<UserService>,
    path: web::Path<String>,
    mut payload: Multipart,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let user_id = path.into_inner();

    // Get current user from JWT claims
    let claims = req.get_claims().ok_or_else(|| {
        warn!("Failed to get claims from request for avatar upload");
        ApiError::Unauthorized("Authentication required".to_string())
    })?;

    // Check authorization
    if !claims.can_access(&user_id) {
        warn!(
            "User {} attempted to upload avatar for user {}",
            claims.sub, user_id
        );
        return Err(ApiError::Unauthorized(
            "You don't have permission to upload avatar for this user".to_string(),
        ));
    }

    // Process the multipart upload
    let mut file_saved = false;
    let mut avatar_url = String::new();

    while let Some(item) = payload.next().await {
        let mut field = item.map_err(|e| {
            warn!("Failed to process multipart field: {}", e);
            ApiError::BadRequest("Failed to process upload".to_string())
        })?;

        // Get content disposition
        let content_disposition = match field.content_disposition() {
            Some(cd) => cd,
            None => continue,
        };
        let field_name = content_disposition.get_name().unwrap_or("");

        if field_name != "avatar" {
            continue;
        }

        // Validate content type
        let content_type = field.content_type().map(|ct| ct.to_string());
        let allowed_types = ["image/jpeg", "image/png", "image/gif", "image/webp"];

        if let Some(ref ct) = content_type {
            if !allowed_types.iter().any(|t| ct.starts_with(t)) {
                return Err(ApiError::BadRequest(
                    "Invalid file type. Only JPEG, PNG, GIF, and WebP are allowed.".to_string(),
                ));
            }
        }

        // Generate unique filename
        let extension = match content_type.as_deref() {
            Some("image/jpeg") => "jpg",
            Some("image/png") => "png",
            Some("image/gif") => "gif",
            Some("image/webp") => "webp",
            _ => "jpg",
        };
        let filename = format!("{}_{}.{}", user_id, Uuid::new_v4(), extension);

        // Create upload directory if it doesn't exist
        let upload_dir = Path::new(&CONFIG.upload_dir);
        if !upload_dir.exists() {
            std::fs::create_dir_all(upload_dir).map_err(|e| {
                warn!("Failed to create upload directory: {}", e);
                ApiError::InternalServerError("Failed to save file".to_string())
            })?;
        }

        let filepath = upload_dir.join(&filename);

        // Create the file
        let mut file = std::fs::File::create(&filepath).map_err(|e| {
            warn!("Failed to create file: {}", e);
            ApiError::InternalServerError("Failed to save file".to_string())
        })?;

        // Write the file content with size limit (5MB)
        let max_size: usize = 5 * 1024 * 1024;
        let mut total_size: usize = 0;

        while let Some(chunk) = field.next().await {
            let data = chunk.map_err(|e| {
                warn!("Failed to read chunk: {}", e);
                ApiError::BadRequest("Failed to read file data".to_string())
            })?;

            total_size += data.len();
            if total_size > max_size {
                // Clean up the partial file
                let _ = std::fs::remove_file(&filepath);
                return Err(ApiError::BadRequest(
                    "File too large. Maximum size is 5MB.".to_string(),
                ));
            }

            file.write_all(&data).map_err(|e| {
                warn!("Failed to write file: {}", e);
                ApiError::InternalServerError("Failed to save file".to_string())
            })?;
        }

        avatar_url = format!("/uploads/{}", filename);
        file_saved = true;
        break;
    }

    if !file_saved {
        return Err(ApiError::BadRequest(
            "No avatar file provided. Please upload a file with field name 'avatar'.".to_string(),
        ));
    }

    // Update user's avatar URL in database
    let updated_user = user_service.update_avatar(&user_id, &avatar_url).await?;
    let user_response: UserResponse = updated_user.into();

    info!("Successfully uploaded avatar for user: {}", user_id);
    Ok(HttpResponse::Ok().json(ApiResponse::success(
        "Avatar uploaded successfully",
        user_response,
    )))
}

/// DELETE /api/users/{id}/avatar - Delete user avatar
/// Users can delete their own avatar, admins can delete for any user
pub async fn delete_avatar(
    user_service: web::Data<UserService>,
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let user_id = path.into_inner();

    // Get current user from JWT claims
    let claims = req.get_claims().ok_or_else(|| {
        warn!("Failed to get claims from request for avatar delete");
        ApiError::Unauthorized("Authentication required".to_string())
    })?;

    // Check authorization
    if !claims.can_access(&user_id) {
        warn!(
            "User {} attempted to delete avatar for user {}",
            claims.sub, user_id
        );
        return Err(ApiError::Unauthorized(
            "You don't have permission to delete avatar for this user".to_string(),
        ));
    }

    // Get current user to find avatar path
    let user = user_service
        .get_user_by_id(&user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("User not found".to_string()))?;

    // Delete the avatar file if it exists
    if let Some(ref avatar_url) = user.profile.avatar_url {
        if avatar_url.starts_with("/uploads/") {
            let filename = avatar_url.trim_start_matches("/uploads/");
            let filepath = Path::new(&CONFIG.upload_dir).join(filename);
            if filepath.exists() {
                let _ = std::fs::remove_file(&filepath);
            }
        }
    }

    // Update user's avatar URL in database
    let updated_user = user_service.delete_avatar(&user_id).await?;
    let user_response: UserResponse = updated_user.into();

    info!("Successfully deleted avatar for user: {}", user_id);
    Ok(HttpResponse::Ok().json(ApiResponse::success(
        "Avatar deleted successfully",
        user_response,
    )))
}
