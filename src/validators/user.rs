//! User-related custom validators.

use validator::ValidationError;

use crate::constants::{ERR_INVALID_ROLE, ROLE_ADMIN, ROLE_USER};

/// Custom validator for role field.
/// Validates that the role is either 'admin' or 'user'.
pub fn validate_role(role: &str) -> Result<(), ValidationError> {
    match role.to_lowercase().as_str() {
        r if r == ROLE_ADMIN || r == ROLE_USER => Ok(()),
        _ => {
            let mut error = ValidationError::new("invalid_role");
            error.message = Some(ERR_INVALID_ROLE.into());
            Err(error)
        }
    }
}
