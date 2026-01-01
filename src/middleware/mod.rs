//! Middleware module for authentication, authorization, and rate limiting.
//!
//! This module provides:
//! - `AuthMiddleware` - JWT authentication middleware for protected routes
//! - `RequestExt` - Extension trait for extracting claims from requests
//! - Auth helper functions for common authorization patterns
//! - Rate limiting middleware for protecting auth endpoints

mod auth_helpers;
mod auth_middleware;
mod rate_limiter;
mod request_ext;

// Re-export auth middleware
pub use auth_middleware::AuthMiddleware;

// Re-export request extension trait
pub use request_ext::RequestExt;

// Re-export auth helper functions
pub use auth_helpers::{prevent_self_action, require_access, require_admin, require_auth};

// Re-export rate limiting
pub use rate_limiter::create_auth_rate_limiter_config;
