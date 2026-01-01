//! User management handlers for CRUD operations and profile management.

use actix_web::{web, HttpRequest, HttpResponse};
use log::{debug, info, warn};
use validator::Validate;

use crate::constants::{
    ERR_AUTH_REQUIRED, ERR_CHANGE_OWN_PASSWORD_ONLY, ERR_NO_PERMISSION_DELETE_ACCOUNT,
    ERR_NO_PERMISSION_UPDATE_PROFILE, ERR_USER_NOT_FOUND, MSG_PASSWORD_CHANGED, MSG_USER_DELETED,
    MSG_USER_FOUND, MSG_USER_PROFILE_RETRIEVED, MSG_USER_UPDATED,
};
use crate::errors::ApiError;
use crate::middleware::RequestExt;
use crate::models::{
    ApiResponse, ChangePasswordRequest, PaginatedResponse, UpdateUserRequest, UserResponse,
};
use crate::services::UserService;
use crate::validators::validation_errors_to_api_error;

/// List all users with pagination and optional filters
#[utoipa::path(
    get,
    path = "/api/users",
    tag = "Users",
    params(
        ("page" = Option<u64>, Query, description = "Page number (default: 1)"),
        ("per_page" = Option<u64>, Query, description = "Items per page (default: 10, max: 100)"),
        ("role" = Option<String>, Query, description = "Filter by role: 'admin' or 'user'"),
        ("is_active" = Option<bool>, Query, description = "Filter by active status"),
        ("search" = Option<String>, Query, description = "Search by username, email, or name")
    ),
    responses(
        (status = 200, description = "List of users", body = crate::models::PaginatedResponse<crate::models::UserResponse>),
        (status = 401, description = "Unauthorized", body = crate::models::ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    )
)]
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

/// Get a specific user by ID
#[utoipa::path(
    get,
    path = "/api/users/{id}",
    tag = "Users",
    params(
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User found", body = UserResponse),
        (status = 401, description = "Unauthorized", body = crate::models::ErrorResponse),
        (status = 404, description = "User not found", body = crate::models::ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    )
)]
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
            ApiError::NotFound(ERR_USER_NOT_FOUND.to_string())
        })?;

    let user_response: UserResponse = user.into();
    info!("Successfully fetched user: {}", user_id);
    Ok(HttpResponse::Ok().json(ApiResponse::success(MSG_USER_FOUND, user_response)))
}

/// Get the currently authenticated user's profile
#[utoipa::path(
    get,
    path = "/api/users/me",
    tag = "Users",
    responses(
        (status = 200, description = "Current user profile", body = UserResponse),
        (status = 401, description = "Unauthorized", body = crate::models::ErrorResponse),
        (status = 404, description = "User not found", body = crate::models::ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn get_current_user(
    user_service: web::Data<UserService>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let claims = req.get_claims().ok_or_else(|| {
        warn!("Failed to get claims from request");
        ApiError::Unauthorized(ERR_AUTH_REQUIRED.to_string())
    })?;

    debug!("Fetching current user with id: {}", claims.sub);

    let user = user_service
        .get_user_by_id(&claims.sub)
        .await?
        .ok_or_else(|| {
            warn!("Current user not found with id: {}", claims.sub);
            ApiError::NotFound(ERR_USER_NOT_FOUND.to_string())
        })?;

    let user_response: UserResponse = user.into();
    info!("Successfully fetched current user: {}", claims.sub);
    Ok(HttpResponse::Ok().json(ApiResponse::success(
        MSG_USER_PROFILE_RETRIEVED,
        user_response,
    )))
}

/// Update a user's profile
///
/// Admins can update any user, regular users can only update themselves.
#[utoipa::path(
    put,
    path = "/api/users/{id}",
    tag = "Users",
    params(
        ("id" = String, Path, description = "User ID")
    ),
    request_body = UpdateUserRequest,
    responses(
        (status = 200, description = "User updated", body = UserResponse),
        (status = 400, description = "Validation error", body = crate::models::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::models::ErrorResponse),
        (status = 404, description = "User not found", body = crate::models::ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    )
)]
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
        ApiError::Unauthorized(ERR_AUTH_REQUIRED.to_string())
    })?;

    // Check authorization: user can update their own profile, or admin can update any user
    if !claims.can_access(&user_id) {
        warn!(
            "User {} (role: {}) attempted to update profile of user {}",
            claims.sub, claims.role, user_id
        );
        return Err(ApiError::Unauthorized(
            ERR_NO_PERMISSION_UPDATE_PROFILE.to_string(),
        ));
    }

    // Log if admin is updating another user
    if claims.is_admin() && claims.sub != user_id {
        info!("Admin {} updating profile of user {}", claims.sub, user_id);
    }

    // Validate input
    body.validate().map_err(|e| {
        warn!("Validation failed for update user");
        validation_errors_to_api_error(e)
    })?;

    info!("Updating user profile for user_id: {}", user_id);
    let updated_user = user_service
        .update_user(&user_id, body.into_inner())
        .await?;
    let user_response: UserResponse = updated_user.into();

    info!("Successfully updated user: {}", user_id);
    Ok(HttpResponse::Ok().json(ApiResponse::success(MSG_USER_UPDATED, user_response)))
}

/// Delete a user account
///
/// Admins can delete any user, regular users can only delete themselves.
#[utoipa::path(
    delete,
    path = "/api/users/{id}",
    tag = "Users",
    params(
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User deleted successfully"),
        (status = 401, description = "Unauthorized", body = crate::models::ErrorResponse),
        (status = 404, description = "User not found", body = crate::models::ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn delete_user(
    user_service: web::Data<UserService>,
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let user_id = path.into_inner();

    // Get current user from JWT claims
    let claims = req.get_claims().ok_or_else(|| {
        warn!("Failed to get claims from request for delete");
        ApiError::Unauthorized(ERR_AUTH_REQUIRED.to_string())
    })?;

    // Check authorization: user can delete their own account, or admin can delete any user
    if !claims.can_access(&user_id) {
        warn!(
            "User {} (role: {}) attempted to delete account of user {}",
            claims.sub, claims.role, user_id
        );
        return Err(ApiError::Unauthorized(
            ERR_NO_PERMISSION_DELETE_ACCOUNT.to_string(),
        ));
    }

    // Log if admin is deleting another user
    if claims.is_admin() && claims.sub != user_id {
        info!("Admin {} deleting account of user {}", claims.sub, user_id);
    }

    info!("Deleting user account for user_id: {}", user_id);
    user_service.delete_user(&user_id).await?;

    info!("Successfully deleted user: {}", user_id);
    Ok(HttpResponse::Ok().json(ApiResponse::<()>::message(MSG_USER_DELETED)))
}

/// Change a user's password
///
/// Users can only change their own password by providing their current password.
#[utoipa::path(
    patch,
    path = "/api/users/{id}/password",
    tag = "Users",
    params(
        ("id" = String, Path, description = "User ID")
    ),
    request_body = ChangePasswordRequest,
    responses(
        (status = 200, description = "Password changed successfully"),
        (status = 400, description = "Validation error or wrong current password", body = crate::models::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::models::ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    )
)]
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
        ApiError::Unauthorized(ERR_AUTH_REQUIRED.to_string())
    })?;

    // Password changes always require knowing the current password,
    // so users (including admins) can only change their own password
    if claims.sub != user_id {
        warn!(
            "User {} (role: {}) attempted to change password of user {}",
            claims.sub, claims.role, user_id
        );
        return Err(ApiError::Unauthorized(
            ERR_CHANGE_OWN_PASSWORD_ONLY.to_string(),
        ));
    }

    // Validate input
    body.validate().map_err(|e| {
        warn!("Validation failed for change password");
        validation_errors_to_api_error(e)
    })?;

    info!("Changing password for user_id: {}", user_id);
    user_service
        .change_password(&user_id, body.into_inner())
        .await?;

    info!("Successfully changed password for user: {}", user_id);
    Ok(HttpResponse::Ok().json(ApiResponse::<()>::message(MSG_PASSWORD_CHANGED)))
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
