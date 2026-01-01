//! Authentication handlers for user registration, login, and logout.

use actix_web::{web, HttpResponse};
use validator::Validate;

use crate::constants::{MSG_LOGIN_SUCCESS, MSG_LOGOUT_SUCCESS, MSG_USER_REGISTERED};
use crate::errors::ApiError;
use crate::models::{ApiResponse, AuthResponse, LoginRequest, RegisterRequest, UserResponse};
use crate::services::{AuthService, UserService};
use crate::validators::validation_errors_to_api_error;

/// Register a new user account
#[utoipa::path(
    post,
    path = "/api/auth/register",
    tag = "Authentication",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "User registered successfully", body = UserResponse),
        (status = 400, description = "Validation error", body = crate::models::ErrorResponse),
        (status = 409, description = "Email or username already exists", body = crate::models::ErrorResponse)
    )
)]
pub async fn register(
    user_service: web::Data<UserService>,
    body: web::Json<RegisterRequest>,
) -> Result<HttpResponse, ApiError> {
    // Validate input
    body.validate().map_err(validation_errors_to_api_error)?;

    let user = user_service.register(body.into_inner()).await?;
    let user_response: UserResponse = user.into();

    Ok(HttpResponse::Created().json(ApiResponse::success(MSG_USER_REGISTERED, user_response)))
}

/// Authenticate a user and get a JWT token
#[utoipa::path(
    post,
    path = "/api/auth/login",
    tag = "Authentication",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = AuthResponse),
        (status = 400, description = "Validation error", body = crate::models::ErrorResponse),
        (status = 401, description = "Invalid credentials", body = crate::models::ErrorResponse)
    )
)]
pub async fn login(
    auth_service: web::Data<AuthService>,
    body: web::Json<LoginRequest>,
) -> Result<HttpResponse, ApiError> {
    // Validate input
    body.validate().map_err(validation_errors_to_api_error)?;

    let (user, token) = auth_service.login(body.into_inner()).await?;

    Ok(HttpResponse::Ok().json(AuthResponse {
        success: true,
        message: MSG_LOGIN_SUCCESS.to_string(),
        token,
        user: user.into(),
    }))
}

/// Logout the current user
#[utoipa::path(
    post,
    path = "/api/auth/logout",
    tag = "Authentication",
    responses(
        (status = 200, description = "Logout successful")
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn logout() -> Result<HttpResponse, ApiError> {
    // For JWT-based auth, logout is typically handled client-side by removing the token
    // Server-side, you might want to implement a token blacklist for additional security
    Ok(HttpResponse::Ok().json(ApiResponse::<()>::message(MSG_LOGOUT_SUCCESS)))
}
