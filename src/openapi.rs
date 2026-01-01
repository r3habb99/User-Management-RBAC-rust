use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::models::{
    AuthResponse, BulkUpdateResponse, BulkUpdateResult, BulkUpdateStatusRequest,
    ChangePasswordRequest, ErrorResponse, HealthResponse, LoginRequest, PaginatedResponse,
    RegisterRequest, Role, UpdateRoleRequest, UpdateStatusRequest, UpdateUserRequest,
    UserProfileResponse, UserResponse, UserStats,
};

/// OpenAPI documentation for the User Management API
#[derive(OpenApi)]
#[openapi(
    info(
        title = "User Management API",
        version = "1.0.0",
        description = "A comprehensive REST API for user management with authentication, authorization, and profile management features.",
        license(name = "MIT", url = "https://opensource.org/licenses/MIT"),
        contact(name = "API Support", email = "support@example.com")
    ),
    servers(
        (url = "http://localhost:8080", description = "Local development server"),
        (url = "http://0.0.0.0:8080", description = "Docker development server")
    ),
    tags(
        (name = "Health", description = "Health check endpoints"),
        (name = "Authentication", description = "User authentication endpoints (register, login, logout)"),
        (name = "Users", description = "User management endpoints (CRUD operations, profile management)"),
        (name = "Admin", description = "Admin-only endpoints (statistics, bulk operations)")
    ),
    paths(
        crate::handlers::register,
        crate::handlers::login,
        crate::handlers::logout,
        crate::handlers::get_users,
        crate::handlers::get_user,
        crate::handlers::get_current_user,
        crate::handlers::update_user,
        crate::handlers::delete_user,
        crate::handlers::change_password,
        crate::handlers::update_role,
        crate::handlers::update_status,
        crate::handlers::upload_avatar,
        crate::handlers::delete_avatar,
        crate::handlers::get_user_stats,
        crate::handlers::bulk_update_status,
        crate::routes::health_check
    ),
    components(
        schemas(
            RegisterRequest,
            LoginRequest,
            UpdateUserRequest,
            ChangePasswordRequest,
            UpdateRoleRequest,
            UpdateStatusRequest,
            BulkUpdateStatusRequest,
            Role,
            UserResponse,
            UserProfileResponse,
            AuthResponse,
            UserStats,
            BulkUpdateResponse,
            BulkUpdateResult,
            PaginatedResponse<UserResponse>,
            ErrorResponse,
            HealthResponse
        )
    ),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;

/// Security configuration for Bearer token authentication
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .description(Some(
                            "JWT token obtained from the /api/auth/login endpoint",
                        ))
                        .build(),
                ),
            );
        }
    }
}

