//! Pagination constants for list endpoints.

/// Default number of items per page when not specified in the request.
pub const DEFAULT_PAGE_SIZE: u64 = 10;

/// Maximum allowed items per page to prevent excessive data retrieval.
pub const MAX_PAGE_SIZE: u64 = 100;

/// Default starting page number.
pub const DEFAULT_PAGE_NUMBER: u64 = 1;

