//! JWT Claims model.

use serde::{Deserialize, Serialize};

use crate::constants::ROLE_ADMIN;

/// JWT Claims structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String, // user_id
    pub email: String,
    pub role: String, // user role (admin/user)
    pub exp: usize,   // expiration timestamp
    pub iat: usize,   // issued at timestamp
}

impl Claims {
    /// Check if the claims belong to an admin user
    pub fn is_admin(&self) -> bool {
        self.role == ROLE_ADMIN
    }

    /// Check if the claims belong to the specified user ID
    pub fn is_user(&self, user_id: &str) -> bool {
        self.sub == user_id
    }

    /// Check if the user can access a resource (either admin or owner)
    pub fn can_access(&self, user_id: &str) -> bool {
        self.is_admin() || self.is_user(user_id)
    }
}
