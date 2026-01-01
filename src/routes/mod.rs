use actix_web::web;

use crate::handlers;
use crate::middleware::AuthMiddleware;

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            // Health check
            .route("/health", web::get().to(health_check))
            // Auth routes (public)
            .service(
                web::scope("/auth")
                    .route("/register", web::post().to(handlers::register))
                    .route("/login", web::post().to(handlers::login))
                    .route("/logout", web::post().to(handlers::logout)),
            )
            // User routes (protected)
            .service(
                web::scope("/users")
                    .wrap(AuthMiddleware)
                    // Get current authenticated user - must be before /{id} to avoid conflict
                    .route("/me", web::get().to(handlers::get_current_user))
                    // List all users with pagination and filters
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
                    .route("/{id}/status", web::patch().to(handlers::update_status)),
            )
            // Admin routes (protected, admin only)
            .service(
                web::scope("/admin")
                    .wrap(AuthMiddleware)
                    // Get user statistics
                    .route("/stats", web::get().to(handlers::get_user_stats)),
            ),
    );
}

async fn health_check() -> actix_web::HttpResponse {
    actix_web::HttpResponse::Ok().json(serde_json::json!({
        "status": "OK",
        "message": "Server is running"
    }))
}
