//! Request extension trait for extracting claims from HTTP requests.

use actix_web::HttpMessage;

use crate::models::Claims;

/// Extension trait for extracting JWT claims from HTTP requests.
///
/// This trait provides a convenient way to access the authenticated user's
/// claims that were added by the AuthMiddleware.
pub trait RequestExt {
    /// Get the JWT claims from the request extensions.
    ///
    /// Returns `Some(Claims)` if the request was authenticated,
    /// or `None` if no claims are present.
    fn get_claims(&self) -> Option<Claims>;
}

impl RequestExt for actix_web::HttpRequest {
    fn get_claims(&self) -> Option<Claims> {
        self.extensions().get::<Claims>().cloned()
    }
}
