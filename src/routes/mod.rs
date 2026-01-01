use actix_governor::Governor;
use actix_web::web;

use crate::handlers;
use crate::middleware::{create_auth_rate_limiter_config, AuthMiddleware};
use crate::services::TokenBlacklist;

pub fn configure_routes(cfg: &mut web::ServiceConfig, token_blacklist: TokenBlacklist) {
    // Create rate limiter configuration for auth endpoints
    let auth_rate_limiter_config = create_auth_rate_limiter_config();

    cfg.service(
        web::scope("/api")
            // Health check
            .route("/health", web::get().to(health_check))
            // Auth routes (public, rate-limited)
            .service(
                web::scope("/auth")
                    .wrap(Governor::new(&auth_rate_limiter_config))
                    .route("/register", web::post().to(handlers::register))
                    .route("/login", web::post().to(handlers::login))
                    // Logout is protected - requires valid token to blacklist it
                    .route(
                        "/logout",
                        web::post()
                            .to(handlers::logout)
                            .wrap(AuthMiddleware::new(token_blacklist.clone())),
                    ),
            )
            // User routes (protected)
            .service(
                web::scope("/users")
                    .wrap(AuthMiddleware::new(token_blacklist.clone()))
                    // Get current authenticated user - must be before /{id} to avoid conflict
                    .route("/me", web::get().to(handlers::get_current_user))
                    // List all users with pagination, filters, and search
                    .route("", web::get().to(handlers::get_users))
                    // Get specific user by ID
                    .route("/{id}", web::get().to(handlers::get_user))
                    // Update user profile
                    .route("/{id}", web::put().to(handlers::update_user))
                    // Delete user account
                    .route("/{id}", web::delete().to(handlers::delete_user))
                    // Change user password
                    .route("/{id}/password", web::patch().to(handlers::change_password))
                    // Update user role (admin only)
                    .route("/{id}/role", web::patch().to(handlers::update_role))
                    // Update user active status (admin only)
                    .route("/{id}/status", web::patch().to(handlers::update_status))
                    // Upload user avatar
                    .route("/{id}/avatar", web::post().to(handlers::upload_avatar))
                    // Delete user avatar
                    .route("/{id}/avatar", web::delete().to(handlers::delete_avatar)),
            )
            // Admin routes (protected, admin only)
            .service(
                web::scope("/admin")
                    .wrap(AuthMiddleware::new(token_blacklist.clone()))
                    // Get user statistics
                    .route("/stats", web::get().to(handlers::get_user_stats))
                    // Bulk update user status
                    .route(
                        "/users/bulk-status",
                        web::patch().to(handlers::bulk_update_status),
                    ),
            ),
    );
}

/// Health check endpoint
#[utoipa::path(
    get,
    path = "/api/health",
    tag = "Health",
    responses(
        (status = 200, description = "Server is healthy", body = crate::models::HealthResponse)
    )
)]
pub async fn health_check() -> actix_web::HttpResponse {
    actix_web::HttpResponse::Ok().json(serde_json::json!({
        "status": "OK",
        "message": "Server is running"
    }))
}
