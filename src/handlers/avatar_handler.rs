//! Avatar upload and deletion handlers.

use actix_multipart::Multipart;
use actix_web::{web, HttpRequest, HttpResponse};
use futures::StreamExt;
use log::{info, warn};
use std::io::Write;
use std::path::Path;
use uuid::Uuid;

use crate::config::CONFIG;
use crate::errors::ApiError;
use crate::middleware::RequestExt;
use crate::models::{ApiResponse, UserResponse};
use crate::services::AvatarService;

/// Upload a user's avatar image
///
/// Users can upload their own avatar, admins can upload for any user.
/// Accepts JPEG, PNG, GIF, and WebP images. Maximum file size is 5MB.
#[utoipa::path(
    post,
    path = "/api/users/{id}/avatar",
    tag = "Users",
    params(
        ("id" = String, Path, description = "User ID")
    ),
    request_body(content_type = "multipart/form-data", description = "Avatar image file"),
    responses(
        (status = 200, description = "Avatar uploaded successfully", body = UserResponse),
        (status = 400, description = "Invalid file type or size", body = crate::models::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::models::ErrorResponse),
        (status = 404, description = "User not found", body = crate::models::ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn upload_avatar(
    avatar_service: web::Data<AvatarService>,
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
    let updated_user = avatar_service.update_avatar(&user_id, &avatar_url).await?;
    let user_response: UserResponse = updated_user.into();

    info!("Successfully uploaded avatar for user: {}", user_id);
    Ok(HttpResponse::Ok().json(ApiResponse::success(
        "Avatar uploaded successfully",
        user_response,
    )))
}

/// Delete a user's avatar image
///
/// Users can delete their own avatar, admins can delete for any user.
#[utoipa::path(
    delete,
    path = "/api/users/{id}/avatar",
    tag = "Users",
    params(
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "Avatar deleted successfully", body = UserResponse),
        (status = 401, description = "Unauthorized", body = crate::models::ErrorResponse),
        (status = 404, description = "User not found", body = crate::models::ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn delete_avatar(
    avatar_service: web::Data<AvatarService>,
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
    let user = avatar_service
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
    let updated_user = avatar_service.delete_avatar(&user_id).await?;
    let user_response: UserResponse = updated_user.into();

    info!("Successfully deleted avatar for user: {}", user_id);
    Ok(HttpResponse::Ok().json(ApiResponse::success(
        "Avatar deleted successfully",
        user_response,
    )))
}
