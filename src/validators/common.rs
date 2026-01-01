//! Common validation utilities and helpers.

use validator::ValidationErrors;

use crate::errors::ApiError;

/// Allowed image content types for avatar uploads.
pub const ALLOWED_AVATAR_TYPES: [&str; 4] = ["image/jpeg", "image/png", "image/gif", "image/webp"];

/// Maximum file size for avatar uploads (5MB).
pub const MAX_AVATAR_SIZE: usize = 5 * 1024 * 1024;

/// Maximum number of users for bulk operations.
pub const MAX_BULK_SIZE: usize = 100;

/// Convert validator errors to ApiError::ValidationError.
/// 
/// This helper function extracts error messages from ValidationErrors
/// and converts them into a format suitable for API responses.
/// 
/// # Example
/// ```ignore
/// body.validate().map_err(validation_errors_to_api_error)?;
/// ```
pub fn validation_errors_to_api_error(e: ValidationErrors) -> ApiError {
    let errors: Vec<String> = e
        .field_errors()
        .iter()
        .flat_map(|(_, errs)| {
            errs.iter()
                .map(|e| e.message.clone().unwrap_or_default().to_string())
        })
        .collect();
    ApiError::ValidationError(errors)
}

/// Validate that password confirmation matches the new password.
/// 
/// Returns an error if the passwords don't match.
pub fn validate_password_match(new_password: &str, confirm_password: &str) -> Result<(), ApiError> {
    if new_password != confirm_password {
        return Err(ApiError::BadRequest(
            "New password and confirmation do not match".to_string(),
        ));
    }
    Ok(())
}

/// Validate that new password is different from current password.
/// 
/// Returns an error if the passwords are the same.
pub fn validate_password_different(current_password: &str, new_password: &str) -> Result<(), ApiError> {
    if current_password == new_password {
        return Err(ApiError::BadRequest(
            "New password must be different from current password".to_string(),
        ));
    }
    Ok(())
}

/// Validate avatar content type.
/// 
/// Returns an error if the content type is not an allowed image type.
pub fn validate_avatar_content_type(content_type: Option<&str>) -> Result<(), ApiError> {
    match content_type {
        Some(ct) if ALLOWED_AVATAR_TYPES.iter().any(|t| ct.starts_with(t)) => Ok(()),
        _ => Err(ApiError::BadRequest(
            "Invalid file type. Only JPEG, PNG, GIF, and WebP are allowed.".to_string(),
        )),
    }
}

/// Get file extension from content type.
/// 
/// Returns the appropriate file extension for the given content type.
pub fn get_extension_from_content_type(content_type: Option<&str>) -> &'static str {
    match content_type {
        Some("image/jpeg") => "jpg",
        Some("image/png") => "png",
        Some("image/gif") => "gif",
        Some("image/webp") => "webp",
        _ => "jpg",
    }
}

/// Validate avatar file size.
/// 
/// Returns an error if the file size exceeds the maximum allowed size.
pub fn validate_avatar_size(size: usize) -> Result<(), ApiError> {
    if size > MAX_AVATAR_SIZE {
        return Err(ApiError::BadRequest(
            "File too large. Maximum size is 5MB.".to_string(),
        ));
    }
    Ok(())
}

/// Validate bulk user IDs for bulk operations.
/// 
/// Returns an error if the list is empty or exceeds the maximum size.
pub fn validate_bulk_user_ids(user_ids: &[String]) -> Result<(), ApiError> {
    if user_ids.is_empty() {
        return Err(ApiError::BadRequest(
            "At least one user ID is required".to_string(),
        ));
    }
    
    if user_ids.len() > MAX_BULK_SIZE {
        return Err(ApiError::BadRequest(format!(
            "Maximum {} users can be updated at once",
            MAX_BULK_SIZE
        )));
    }
    
    Ok(())
}

