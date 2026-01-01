//! Error code constants for API responses.
//!
//! These codes provide a machine-readable identifier for each error type,
//! making it easier for API clients to handle errors programmatically.

// Validation errors
pub const CODE_VALIDATION_FAILED: &str = "VALIDATION_FAILED";
pub const CODE_VALIDATION_ERROR: &str = "VALIDATION_ERROR";
pub const CODE_INVALID_FORMAT: &str = "INVALID_FORMAT";

// Bulk operation errors
pub const CODE_BULK_REQUIRED: &str = "BULK_REQUIRED";
pub const CODE_BULK_LIMIT_EXCEEDED: &str = "BULK_LIMIT_EXCEEDED";

// Authentication errors
pub const CODE_AUTH_REQUIRED: &str = "AUTH_REQUIRED";
pub const CODE_INVALID_TOKEN: &str = "INVALID_TOKEN";
pub const CODE_INVALID_CREDENTIALS: &str = "INVALID_CREDENTIALS";
pub const CODE_ACCOUNT_DEACTIVATED: &str = "ACCOUNT_DEACTIVATED";

// User errors
pub const CODE_USER_NOT_FOUND: &str = "USER_NOT_FOUND";
pub const CODE_EMAIL_EXISTS: &str = "EMAIL_EXISTS";
pub const CODE_USERNAME_EXISTS: &str = "USERNAME_EXISTS";
pub const CODE_INVALID_USER_ID: &str = "INVALID_USER_ID";

// Authorization errors
pub const CODE_FORBIDDEN: &str = "FORBIDDEN";
pub const CODE_ADMIN_REQUIRED: &str = "ADMIN_REQUIRED";
pub const CODE_SELF_ACTION_FORBIDDEN: &str = "SELF_ACTION_FORBIDDEN";

// Password errors
pub const CODE_WRONG_PASSWORD: &str = "WRONG_PASSWORD";
pub const CODE_PASSWORD_MISMATCH: &str = "PASSWORD_MISMATCH";
pub const CODE_SAME_PASSWORD: &str = "SAME_PASSWORD";

// File errors
pub const CODE_INVALID_FILE_TYPE: &str = "INVALID_FILE_TYPE";
pub const CODE_FILE_TOO_LARGE: &str = "FILE_TOO_LARGE";
pub const CODE_FILE_UPLOAD_FAILED: &str = "FILE_UPLOAD_FAILED";

// Generic errors
pub const CODE_BAD_REQUEST: &str = "BAD_REQUEST";
pub const CODE_NOT_FOUND: &str = "NOT_FOUND";
pub const CODE_CONFLICT: &str = "CONFLICT";
pub const CODE_INTERNAL_ERROR: &str = "INTERNAL_ERROR";
