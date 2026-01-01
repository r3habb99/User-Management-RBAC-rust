//! Authentication and authorization helper functions.
//!
//! These helpers reduce boilerplate in handlers by providing common patterns for:
//! - Extracting claims from authenticated requests
//! - Requiring admin privileges
//! - Checking resource access permissions
//! - Preventing self-targeted actions

use actix_web::HttpRequest;
use log::warn;

use crate::constants::ERR_AUTH_REQUIRED;
use crate::errors::ApiError;
use crate::models::Claims;

use super::RequestExt;

/// Extract claims from request or return Unauthorized error.
///
/// Use this at the start of any handler that requires authentication.
///
/// # Example
/// ```ignore
/// let claims = require_auth(&req)?;
/// ```
pub fn require_auth(req: &HttpRequest) -> Result<Claims, ApiError> {
    req.get_claims().ok_or_else(|| {
        warn!("Failed to get claims from request");
        ApiError::Unauthorized(ERR_AUTH_REQUIRED.to_string())
    })
}

/// Require admin role or return Unauthorized error.
///
/// Call this after `require_auth` to ensure the user has admin privileges.
///
/// # Arguments
/// * `claims` - The JWT claims from the authenticated user
/// * `action_msg` - Custom error message describing the action (e.g., "Only administrators can update user roles")
///
/// # Example
/// ```ignore
/// let claims = require_auth(&req)?;
/// require_admin(&claims, ERR_ONLY_ADMINS_ROLES)?;
/// ```
pub fn require_admin(claims: &Claims, action_msg: &str) -> Result<(), ApiError> {
    if !claims.is_admin() {
        warn!("Non-admin user {} attempted admin action", claims.sub);
        return Err(ApiError::Unauthorized(action_msg.to_string()));
    }
    Ok(())
}

/// Check if the user can access a resource (admin or owner).
///
/// Returns an Unauthorized error if the user cannot access the resource.
///
/// # Arguments
/// * `claims` - The JWT claims from the authenticated user
/// * `target_user_id` - The ID of the user whose resource is being accessed
/// * `permission_msg` - Custom error message for permission denied
///
/// # Example
/// ```ignore
/// let claims = require_auth(&req)?;
/// require_access(&claims, &user_id, ERR_NO_PERMISSION_UPDATE_PROFILE)?;
/// ```
pub fn require_access(
    claims: &Claims,
    target_user_id: &str,
    permission_msg: &str,
) -> Result<(), ApiError> {
    if !claims.can_access(target_user_id) {
        warn!(
            "User {} (role: {}) attempted to access resource of user {}",
            claims.sub, claims.role, target_user_id
        );
        return Err(ApiError::Unauthorized(permission_msg.to_string()));
    }
    Ok(())
}

/// Prevent self-targeted actions (e.g., admin deactivating themselves).
///
/// Returns a BadRequest error if the user is attempting an action on themselves.
///
/// # Arguments
/// * `claims` - The JWT claims from the authenticated user
/// * `target_user_id` - The ID of the target user
/// * `self_action_msg` - Custom error message for self-action prevention
///
/// # Example
/// ```ignore
/// let claims = require_auth(&req)?;
/// prevent_self_action(&claims, &user_id, ERR_CANNOT_DEACTIVATE_SELF)?;
/// ```
pub fn prevent_self_action(
    claims: &Claims,
    target_user_id: &str,
    self_action_msg: &str,
) -> Result<(), ApiError> {
    if claims.sub == target_user_id {
        warn!(
            "User {} attempted self-targeted action: {}",
            claims.sub, self_action_msg
        );
        return Err(ApiError::BadRequest(self_action_msg.to_string()));
    }
    Ok(())
}

