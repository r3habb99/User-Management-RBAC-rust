//! Error message constants used throughout the application.

// Authentication errors
pub const ERR_AUTH_REQUIRED: &str = "Authentication required";
pub const ERR_INVALID_AUTH_HEADER: &str = "Missing or invalid authorization header";
pub const ERR_INVALID_TOKEN: &str = "Invalid or expired token";

// User errors
pub const ERR_USER_NOT_FOUND: &str = "User not found";
pub const ERR_INVALID_USER_ID: &str = "Invalid user ID format";
pub const ERR_EMAIL_EXISTS: &str = "Email already registered";
pub const ERR_USERNAME_EXISTS: &str = "Username already taken";
pub const ERR_INVALID_CREDENTIALS: &str = "Invalid email or password";
pub const ERR_ACCOUNT_DEACTIVATED: &str = "Account is deactivated";

// Authorization errors
pub const ERR_ONLY_ADMINS_ROLES: &str = "Only administrators can update user roles";
pub const ERR_ONLY_ADMINS_STATUS: &str = "Only administrators can update user status";
pub const ERR_ONLY_ADMINS_STATS: &str = "Only administrators can view user statistics";
pub const ERR_ONLY_ADMINS_BULK: &str = "Only administrators can perform bulk operations";
pub const ERR_CANNOT_DEACTIVATE_SELF: &str = "Administrators cannot deactivate themselves";
pub const ERR_CANNOT_DEMOTE_SELF: &str =
    "Administrators cannot demote themselves. Ask another admin to do this.";
pub const ERR_NO_PERMISSION_UPDATE_PROFILE: &str =
    "You don't have permission to update this user's profile";
pub const ERR_NO_PERMISSION_DELETE_ACCOUNT: &str =
    "You don't have permission to delete this user's account";
pub const ERR_NO_PERMISSION_AVATAR_UPLOAD: &str =
    "You don't have permission to upload avatar for this user";
pub const ERR_NO_PERMISSION_AVATAR_DELETE: &str =
    "You don't have permission to delete avatar for this user";
pub const ERR_CHANGE_OWN_PASSWORD_ONLY: &str =
    "You can only change your own password. For other users, use the password reset feature.";

// Password errors
pub const ERR_PASSWORD_MISMATCH: &str = "New password and confirmation do not match";
pub const ERR_SAME_PASSWORD: &str = "New password must be different from current password";
pub const ERR_WRONG_PASSWORD: &str = "Current password is incorrect";

// Validation errors
pub const ERR_INVALID_ROLE: &str = "Role must be either 'admin' or 'user'";
pub const ERR_INVALID_FILE_TYPE: &str =
    "Invalid file type. Only JPEG, PNG, GIF, and WebP are allowed.";
pub const ERR_FILE_TOO_LARGE: &str = "File too large. Maximum size is 5MB.";
pub const ERR_NO_AVATAR_FILE: &str =
    "No avatar file provided. Please upload a file with field name 'avatar'.";
pub const ERR_FAILED_PROCESS_UPLOAD: &str = "Failed to process upload";
pub const ERR_FAILED_READ_FILE: &str = "Failed to read file data";
pub const ERR_FAILED_SAVE_FILE: &str = "Failed to save file";
pub const ERR_FAILED_FETCH_USER: &str = "Failed to fetch updated user";
pub const ERR_AT_LEAST_ONE_USER_ID: &str = "At least one user ID is required";
pub const ERR_CANNOT_DEACTIVATE_YOURSELF: &str = "Cannot deactivate yourself";
pub const ERR_WEAK_PASSWORD: &str =
    "Password must contain at least one uppercase, lowercase, digit, and special character";
pub const ERR_INVALID_USERNAME_FORMAT: &str =
    "Username can only contain letters, numbers, underscores, and hyphens";
pub const ERR_INVALID_DATE_FORMAT: &str = "Date must be in YYYY-MM-DD format";
