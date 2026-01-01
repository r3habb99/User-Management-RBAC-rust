use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
use futures::future::{ok, LocalBoxFuture, Ready};
use jsonwebtoken::{decode, DecodingKey, Validation};
use std::rc::Rc;

use crate::config::CONFIG;
use crate::constants::{ERR_INVALID_AUTH_HEADER, ERR_INVALID_TOKEN};
use crate::errors::ApiError;
use crate::models::Claims;

pub struct AuthMiddleware;

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
        })
    }
}

pub struct AuthMiddlewareService<S> {
    service: Rc<S>,
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

        Box::pin(async move {
            // Extract Authorization header
            let auth_header = req
                .headers()
                .get("Authorization")
                .and_then(|h| h.to_str().ok());

            let token = match auth_header {
                Some(header) if header.starts_with("Bearer ") => &header[7..],
                _ => {
                    return Err(ApiError::Unauthorized(ERR_INVALID_AUTH_HEADER.to_string()).into());
                }
            };

            // Validate JWT token
            let token_data = decode::<Claims>(
                token,
                &DecodingKey::from_secret(CONFIG.jwt_secret.as_bytes()),
                &Validation::default(),
            )
            .map_err(|_| ApiError::Unauthorized(ERR_INVALID_TOKEN.to_string()))?;

            // Add claims to request extensions for use in handlers
            req.extensions_mut().insert(token_data.claims);

            let res = service.call(req).await?;
            Ok(res)
        })
    }
}

/// Helper to extract claims from request in handlers
pub trait RequestExt {
    fn get_claims(&self) -> Option<Claims>;
}

impl RequestExt for actix_web::HttpRequest {
    fn get_claims(&self) -> Option<Claims> {
        self.extensions().get::<Claims>().cloned()
    }
}
