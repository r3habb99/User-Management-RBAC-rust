//! Generic API response models.

use serde::Serialize;
use utoipa::ToSchema;

/// Generic API response wrapper
#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn success(message: &str, data: T) -> Self {
        Self {
            success: true,
            message: message.to_string(),
            data: Some(data),
        }
    }

    pub fn message(message: &str) -> ApiResponse<()> {
        ApiResponse {
            success: true,
            message: message.to_string(),
            data: None,
        }
    }
}

/// Error response structure
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    /// Whether the request was successful (always false for errors)
    #[schema(example = false)]
    pub success: bool,
    /// Error message
    #[schema(example = "An error occurred")]
    pub message: String,
    /// Detailed validation errors (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
}

/// Health check response
#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    /// Health status
    #[schema(example = "OK")]
    pub status: String,
    /// Status message
    #[schema(example = "Server is running")]
    pub message: String,
}

