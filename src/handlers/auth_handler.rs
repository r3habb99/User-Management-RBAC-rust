//! Authentication handlers for user registration, login, and logout.

use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use log::info;
use validator::Validate;

use crate::constants::{MSG_LOGIN_SUCCESS, MSG_LOGOUT_SUCCESS, MSG_USER_REGISTERED};
use crate::errors::ApiError;
use crate::models::{
    ApiResponse, AuthResponse, Claims, LoginRequest, RegisterRequest, UserResponse,
};
use crate::services::{AuthService, TokenBlacklist, UserService};
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
///
/// This endpoint invalidates the current JWT token by adding it to a server-side
/// blacklist. The token will remain blacklisted until its natural expiration time.
#[utoipa::path(
    post,
    path = "/api/auth/logout",
    tag = "Authentication",
    responses(
        (status = 200, description = "Logout successful"),
        (status = 401, description = "Invalid or missing token", body = crate::models::ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn logout(
    req: HttpRequest,
    token_blacklist: web::Data<TokenBlacklist>,
) -> Result<HttpResponse, ApiError> {
    // Get the token and claims from request extensions (set by AuthMiddleware)
    let claims = req.extensions().get::<Claims>().cloned();
    let token = req.extensions().get::<String>().cloned();

    if let (Some(claims), Some(token)) = (claims, token) {
        // Add token to blacklist with its expiration time
        token_blacklist.blacklist_token(&token, claims.exp).await;
        info!("User {} logged out successfully", claims.sub);
    }

    Ok(HttpResponse::Ok().json(ApiResponse::<()>::message(MSG_LOGOUT_SUCCESS)))
}
