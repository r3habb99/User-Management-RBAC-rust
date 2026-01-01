use actix_web::{web, HttpRequest, HttpResponse};
use log::{debug, info, warn};
use validator::Validate;

use crate::errors::ApiError;
use crate::middleware::RequestExt;
use crate::models::{
    ApiResponse, AuthResponse, ChangePasswordRequest, LoginRequest, PaginatedResponse,
    RegisterRequest, UpdateRoleRequest, UpdateUserRequest, UserResponse,
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
pub async fn get_users(
    user_service: web::Data<UserService>,
    query: web::Query<PaginationQuery>,
) -> Result<HttpResponse, ApiError> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(10).min(100);

    let (users, total) = user_service.get_all_users(page, per_page).await?;
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

#[derive(Debug, serde::Deserialize)]
pub struct PaginationQuery {
    pub page: Option<u64>,
    pub per_page: Option<u64>,
}
