//! Services organized by domain concern.

pub mod auth_service;
pub mod avatar_service;
pub mod user_service;

pub use auth_service::AuthService;
pub use avatar_service::AvatarService;
pub use user_service::UserService;
