//! Application constants module.
//!
//! This module centralizes all constant strings used throughout the application,
//! including error messages, success messages, role definitions, collection names,
//! error codes, and pagination defaults.

pub mod collections;
pub mod error_codes;
pub mod errors;
pub mod messages;
pub mod pagination;
pub mod roles;

pub use collections::*;
pub use error_codes::*;
pub use errors::*;
pub use messages::*;
pub use pagination::*;
pub use roles::*;
