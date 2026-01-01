//! Avatar upload and deletion handlers.

use actix_multipart::Multipart;
use actix_web::{web, HttpRequest, HttpResponse};
use futures::StreamExt;
use log::{info, warn};
use std::io::Write;
use std::path::Path;
use uuid::Uuid;

use crate::config::CONFIG;
use crate::constants::{
    ERR_FAILED_PROCESS_UPLOAD, ERR_FAILED_READ_FILE, ERR_FAILED_SAVE_FILE, ERR_NO_AVATAR_FILE,
    ERR_NO_PERMISSION_AVATAR_DELETE, ERR_NO_PERMISSION_AVATAR_UPLOAD, ERR_USER_NOT_FOUND,
    MSG_AVATAR_DELETED, MSG_AVATAR_UPLOADED,
};
use crate::errors::ApiError;
use crate::middleware::{require_access, require_auth};
use crate::models::{ApiResponse, UserResponse};
use crate::services::AvatarService;
use crate::validators::{
    get_extension_from_content_type, validate_avatar_content_type, validate_avatar_size,
};

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
    let claims = require_auth(&req)?;
    require_access(&claims, &user_id, ERR_NO_PERMISSION_AVATAR_UPLOAD)?;

    // Process the multipart upload
    let mut file_saved = false;
    let mut avatar_url = String::new();

    while let Some(item) = payload.next().await {
        let mut field = item.map_err(|e| {
            warn!("Failed to process multipart field: {}", e);
            ApiError::BadRequest(ERR_FAILED_PROCESS_UPLOAD.to_string())
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
        validate_avatar_content_type(content_type.as_deref())?;

        // Generate unique filename
        let extension = get_extension_from_content_type(content_type.as_deref());
        let filename = format!("{}_{}.{}", user_id, Uuid::new_v4(), extension);

        // Create upload directory if it doesn't exist
        let upload_dir = Path::new(&CONFIG.upload_dir);
        if !upload_dir.exists() {
            std::fs::create_dir_all(upload_dir).map_err(|e| {
                warn!("Failed to create upload directory: {}", e);
                ApiError::InternalServerError(ERR_FAILED_SAVE_FILE.to_string())
            })?;
        }

        let filepath = upload_dir.join(&filename);

        // Create the file
        let mut file = std::fs::File::create(&filepath).map_err(|e| {
            warn!("Failed to create file: {}", e);
            ApiError::InternalServerError(ERR_FAILED_SAVE_FILE.to_string())
        })?;

        // Write the file content with size limit
        let mut total_size: usize = 0;

        while let Some(chunk) = field.next().await {
            let data = chunk.map_err(|e| {
                warn!("Failed to read chunk: {}", e);
                ApiError::BadRequest(ERR_FAILED_READ_FILE.to_string())
            })?;

            total_size += data.len();
            if let Err(e) = validate_avatar_size(total_size) {
                // Clean up the partial file
                let _ = std::fs::remove_file(&filepath);
                return Err(e);
            }

            file.write_all(&data).map_err(|e| {
                warn!("Failed to write file: {}", e);
                ApiError::InternalServerError(ERR_FAILED_SAVE_FILE.to_string())
            })?;
        }

        avatar_url = format!("/uploads/{}", filename);
        file_saved = true;
        break;
    }

    if !file_saved {
        return Err(ApiError::BadRequest(ERR_NO_AVATAR_FILE.to_string()));
    }

    // Update user's avatar URL in database
    let updated_user = avatar_service.update_avatar(&user_id, &avatar_url).await?;
    let user_response: UserResponse = updated_user.into();

    info!("Successfully uploaded avatar for user: {}", user_id);
    Ok(HttpResponse::Ok().json(ApiResponse::success(MSG_AVATAR_UPLOADED, user_response)))
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
    let _claims = require_auth(&req)?;
    require_access(&_claims, &user_id, ERR_NO_PERMISSION_AVATAR_DELETE)?;

    // Get current user to find avatar path
    let user = avatar_service
        .get_user_by_id(&user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(ERR_USER_NOT_FOUND.to_string()))?;

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
    Ok(HttpResponse::Ok().json(ApiResponse::success(MSG_AVATAR_DELETED, user_response)))
}
