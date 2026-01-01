//! Pagination response models.

use serde::Serialize;
use utoipa::ToSchema;

/// Paginated list response
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = PaginatedUserResponse)]
pub struct PaginatedResponse<T: Serialize> {
    /// Whether the request was successful
    pub success: bool,
    /// List of items
    pub data: Vec<T>,
    /// Total number of items
    pub total: u64,
    /// Current page number
    pub page: u64,
    /// Items per page
    pub per_page: u64,
    /// Total number of pages
    pub total_pages: u64,
}
