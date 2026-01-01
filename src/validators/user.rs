//! User-related custom validators.

use lazy_static::lazy_static;
use regex::Regex;
use validator::ValidationError;

use crate::constants::{
    ERR_INVALID_DATE_FORMAT, ERR_INVALID_ROLE, ERR_INVALID_USERNAME_FORMAT, ERR_WEAK_PASSWORD,
    ROLE_ADMIN, ROLE_USER,
};

lazy_static! {
    /// Regex to check for at least one lowercase letter.
    static ref HAS_LOWERCASE: Regex = Regex::new(r"[a-z]").unwrap();

    /// Regex to check for at least one uppercase letter.
    static ref HAS_UPPERCASE: Regex = Regex::new(r"[A-Z]").unwrap();

    /// Regex to check for at least one digit.
    static ref HAS_DIGIT: Regex = Regex::new(r"[0-9]").unwrap();

    /// Regex to check for at least one special character.
    static ref HAS_SPECIAL: Regex = Regex::new(r"[@$!%*?&]").unwrap();

    /// Username regex: only letters, numbers, underscores, and hyphens.
    static ref USERNAME_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9_-]+$").unwrap();
}

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

/// Custom validator for password strength.
///
/// Validates that the password contains:
/// - At least one lowercase letter
/// - At least one uppercase letter
/// - At least one digit
/// - At least one special character (@$!%*?&)
/// - Minimum 8 characters
pub fn validate_password_strength(password: &str) -> Result<(), ValidationError> {
    let is_valid = password.len() >= 8
        && HAS_LOWERCASE.is_match(password)
        && HAS_UPPERCASE.is_match(password)
        && HAS_DIGIT.is_match(password)
        && HAS_SPECIAL.is_match(password);

    if !is_valid {
        let mut error = ValidationError::new("weak_password");
        error.message = Some(ERR_WEAK_PASSWORD.into());
        return Err(error);
    }
    Ok(())
}

/// Custom validator for username format.
///
/// Validates that the username only contains:
/// - Letters (a-z, A-Z)
/// - Numbers (0-9)
/// - Underscores (_)
/// - Hyphens (-)
pub fn validate_username_format(username: &str) -> Result<(), ValidationError> {
    if !USERNAME_REGEX.is_match(username) {
        let mut error = ValidationError::new("invalid_username");
        error.message = Some(ERR_INVALID_USERNAME_FORMAT.into());
        return Err(error);
    }
    Ok(())
}

/// Custom validator for date of birth.
///
/// Validates that the date is in YYYY-MM-DD format.
pub fn validate_date_of_birth(date: &str) -> Result<(), ValidationError> {
    if chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").is_err() {
        let mut error = ValidationError::new("invalid_date");
        error.message = Some(ERR_INVALID_DATE_FORMAT.into());
        return Err(error);
    }
    Ok(())
}
