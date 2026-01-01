//! HTTP request handlers organized by domain.

pub mod admin_handler;
pub mod auth_handler;
pub mod avatar_handler;
pub mod user_handler;

pub use admin_handler::*;
pub use auth_handler::*;
pub use avatar_handler::*;
pub use user_handler::*;
