//! Repository layer for database operations.
//! 
//! This module provides a clean separation between business logic (services)
//! and database operations (repositories), improving testability and maintainability.

pub mod user_repository;

pub use user_repository::UserRepository;

