//! Middleware module for authentication and authorization.
//!
//! This module provides:
//! - `AuthMiddleware` - JWT authentication middleware for protected routes
//! - `RequestExt` - Extension trait for extracting claims from requests
//! - Auth helper functions for common authorization patterns

mod auth_helpers;
mod auth_middleware;
mod request_ext;

// Re-export auth middleware
pub use auth_middleware::AuthMiddleware;

// Re-export request extension trait
pub use request_ext::RequestExt;

// Re-export auth helper functions
pub use auth_helpers::{prevent_self_action, require_access, require_admin, require_auth};
