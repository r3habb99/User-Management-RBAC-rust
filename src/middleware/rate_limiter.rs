//! Rate limiting middleware for authentication endpoints.
//!
//! This module provides rate limiting to protect against brute-force attacks
//! on authentication endpoints like login and registration.

use actix_governor::{GovernorConfig, GovernorConfigBuilder};

/// Create rate limiter configuration for authentication endpoints.
///
/// This creates a strict rate limiter suitable for auth endpoints:
/// - Allows 5 requests burst with 1 request replenished every 6 seconds (10 per minute)
/// - Helps prevent brute-force login attempts
///
/// Usage:
/// ```ignore
/// let config = create_auth_rate_limiter_config();
/// web::scope("/auth").wrap(Governor::new(&config))
/// ```
pub fn create_auth_rate_limiter_config() -> GovernorConfig<
    actix_governor::PeerIpKeyExtractor,
    actix_governor::governor::middleware::NoOpMiddleware<
        actix_governor::governor::clock::QuantaInstant,
    >,
> {
    GovernorConfigBuilder::default()
        .seconds_per_request(6) // Replenish 1 request every 6 seconds = 10 per minute
        .burst_size(5) // Allow burst of up to 5 requests
        .finish()
        .expect("Failed to create auth rate limiter config")
}
