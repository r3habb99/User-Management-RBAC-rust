//! User-related custom validators.

use validator::ValidationError;

/// Custom validator for role field.
/// Validates that the role is either 'admin' or 'user'.
pub fn validate_role(role: &str) -> Result<(), ValidationError> {
    match role.to_lowercase().as_str() {
        "admin" | "user" => Ok(()),
        _ => {
            let mut error = ValidationError::new("invalid_role");
            error.message = Some("Role must be either 'admin' or 'user'".into());
            Err(error)
        }
    }
}

