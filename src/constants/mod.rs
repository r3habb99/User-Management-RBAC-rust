//! Application constants module.
//!
//! This module centralizes all constant strings used throughout the application,
//! including error messages, success messages, role definitions, collection names,
//! and pagination defaults.

pub mod collections;
pub mod errors;
pub mod messages;
pub mod pagination;
pub mod roles;

pub use collections::*;
pub use errors::*;
pub use messages::*;
pub use pagination::*;
pub use roles::*;
