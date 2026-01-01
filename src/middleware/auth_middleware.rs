//! JWT Authentication middleware for protected routes.

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
use futures::future::{ok, LocalBoxFuture, Ready};
use jsonwebtoken::{decode, DecodingKey, Validation};
use std::rc::Rc;

use crate::config::CONFIG;
use crate::constants::{
    CODE_INVALID_TOKEN, CODE_TOKEN_REVOKED, ERR_INVALID_AUTH_HEADER, ERR_INVALID_TOKEN,
    ERR_TOKEN_REVOKED,
};
use crate::errors::ApiError;
use crate::models::Claims;
use crate::services::TokenBlacklist;

/// JWT Authentication middleware.
///
/// This middleware validates JWT tokens from the Authorization header,
/// checks if the token has been blacklisted (logged out), and adds
/// the decoded claims to the request extensions.
pub struct AuthMiddleware {
    blacklist: TokenBlacklist,
}

impl AuthMiddleware {
    /// Create a new AuthMiddleware with the given token blacklist.
    pub fn new(blacklist: TokenBlacklist) -> Self {
        Self { blacklist }
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = AuthMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthMiddlewareService {
            service: Rc::new(service),
            blacklist: self.blacklist.clone(),
        })
    }
}

pub struct AuthMiddlewareService<S> {
    service: Rc<S>,
    blacklist: TokenBlacklist,
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        let blacklist = self.blacklist.clone();

        Box::pin(async move {
            // Extract Authorization header
            let auth_header = req
                .headers()
                .get("Authorization")
                .and_then(|h| h.to_str().ok());

            let token = match auth_header {
                Some(header) if header.starts_with("Bearer ") => &header[7..],
                _ => {
                    return Err(ApiError::Unauthorized {
                        code: CODE_INVALID_TOKEN.to_string(),
                        message: ERR_INVALID_AUTH_HEADER.to_string(),
                    }
                    .into());
                }
            };

            // Check if token is blacklisted (logged out)
            if blacklist.is_blacklisted(token) {
                return Err(ApiError::Unauthorized {
                    code: CODE_TOKEN_REVOKED.to_string(),
                    message: ERR_TOKEN_REVOKED.to_string(),
                }
                .into());
            }

            // Validate JWT token
            let token_data = decode::<Claims>(
                token,
                &DecodingKey::from_secret(CONFIG.jwt_secret.as_bytes()),
                &Validation::default(),
            )
            .map_err(|_| ApiError::Unauthorized {
                code: CODE_INVALID_TOKEN.to_string(),
                message: ERR_INVALID_TOKEN.to_string(),
            })?;

            // Store the raw token in extensions for potential logout
            req.extensions_mut().insert(token.to_string());

            // Add claims to request extensions for use in handlers
            req.extensions_mut().insert(token_data.claims);

            let res = service.call(req).await?;
            Ok(res)
        })
    }
}
