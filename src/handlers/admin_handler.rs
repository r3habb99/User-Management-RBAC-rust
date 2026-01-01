//! Admin-only handlers for user management operations.

use actix_web::{web, HttpRequest, HttpResponse};
use log::{info, warn};
use validator::Validate;

use crate::errors::ApiError;
use crate::middleware::RequestExt;
use crate::models::{
    ApiResponse, BulkUpdateStatusRequest, UpdateRoleRequest, UpdateStatusRequest, UserResponse,
    UserStats,
};
use crate::services::UserService;

/// Update a user's role (admin only)
///
/// Only admins can promote or demote users. Admins cannot demote themselves.
#[utoipa::path(
    patch,
    path = "/api/users/{id}/role",
    tag = "Users",
    params(
        ("id" = String, Path, description = "User ID")
    ),
    request_body = UpdateRoleRequest,
    responses(
        (status = 200, description = "Role updated successfully", body = UserResponse),
        (status = 400, description = "Validation error", body = crate::models::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::models::ErrorResponse),
        (status = 404, description = "User not found", body = crate::models::ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    )
)]
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

/// Update a user's active status (admin only)
///
/// Activate or deactivate a user account. Admins cannot deactivate themselves.
#[utoipa::path(
    patch,
    path = "/api/users/{id}/status",
    tag = "Users",
    params(
        ("id" = String, Path, description = "User ID")
    ),
    request_body = UpdateStatusRequest,
    responses(
        (status = 200, description = "Status updated successfully", body = UserResponse),
        (status = 400, description = "Cannot deactivate yourself", body = crate::models::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::models::ErrorResponse),
        (status = 404, description = "User not found", body = crate::models::ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    )
)]
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

/// Get user statistics (admin only)
///
/// Returns aggregate statistics about users in the system.
#[utoipa::path(
    get,
    path = "/api/admin/stats",
    tag = "Admin",
    responses(
        (status = 200, description = "User statistics", body = UserStats),
        (status = 401, description = "Unauthorized", body = crate::models::ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    )
)]
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

/// Bulk update user status (admin only)
///
/// Activate or deactivate multiple users at once. Maximum 100 users per request.
#[utoipa::path(
    patch,
    path = "/api/admin/users/bulk-status",
    tag = "Admin",
    request_body = BulkUpdateStatusRequest,
    responses(
        (status = 200, description = "Bulk update completed", body = crate::models::BulkUpdateResponse),
        (status = 400, description = "Invalid request", body = crate::models::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::models::ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    )
)]
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
