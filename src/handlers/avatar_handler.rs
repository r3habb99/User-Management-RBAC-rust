//! Avatar upload and deletion handlers.

use actix_multipart::Multipart;
use actix_web::{web, HttpRequest, HttpResponse};
use log::info;

use crate::constants::{
    CODE_USER_NOT_FOUND, ERR_NO_PERMISSION_AVATAR_DELETE, ERR_NO_PERMISSION_AVATAR_UPLOAD,
    ERR_USER_NOT_FOUND, MSG_AVATAR_DELETED, MSG_AVATAR_UPLOADED,
};
use crate::errors::ApiError;
use crate::middleware::{require_access, require_auth};
use crate::models::{ApiResponse, UserResponse};
use crate::services::{AvatarService, FileService};

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
    file_service: web::Data<FileService>,
    path: web::Path<String>,
    mut payload: Multipart,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let user_id = path.into_inner();
    let claims = require_auth(&req)?;
    require_access(&claims, &user_id, ERR_NO_PERMISSION_AVATAR_UPLOAD)?;

    // Delegate file processing to FileService
    let avatar_url = file_service.save_avatar(&user_id, &mut payload).await?;

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
    file_service: web::Data<FileService>,
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
        .ok_or_else(|| ApiError::NotFound {
            code: CODE_USER_NOT_FOUND.to_string(),
            message: ERR_USER_NOT_FOUND.to_string(),
        })?;

    // Delete the avatar file if it exists
    if let Some(ref avatar_url) = user.profile.avatar_url {
        file_service.delete_file(avatar_url)?;
    }

    // Update user's avatar URL in database
    let updated_user = avatar_service.delete_avatar(&user_id).await?;
    let user_response: UserResponse = updated_user.into();

    info!("Successfully deleted avatar for user: {}", user_id);
    Ok(HttpResponse::Ok().json(ApiResponse::success(MSG_AVATAR_DELETED, user_response)))
}
