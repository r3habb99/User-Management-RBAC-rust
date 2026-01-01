use actix_web::{HttpResponse, ResponseError};
use serde::Serialize;
use std::fmt;

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
}

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    Unauthorized(String),
    NotFound(String),
    Conflict(String),
    InternalServerError(String),
    ValidationError(Vec<String>),
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::BadRequest(msg) => write!(f, "Bad Request: {}", msg),
            ApiError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            ApiError::NotFound(msg) => write!(f, "Not Found: {}", msg),
            ApiError::Conflict(msg) => write!(f, "Conflict: {}", msg),
            ApiError::InternalServerError(msg) => write!(f, "Internal Server Error: {}", msg),
            ApiError::ValidationError(errors) => write!(f, "Validation Error: {:?}", errors),
        }
    }
}

impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ApiError::BadRequest(msg) => HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                message: msg.clone(),
                errors: None,
            }),
            ApiError::Unauthorized(msg) => HttpResponse::Unauthorized().json(ErrorResponse {
                success: false,
                message: msg.clone(),
                errors: None,
            }),
            ApiError::NotFound(msg) => HttpResponse::NotFound().json(ErrorResponse {
                success: false,
                message: msg.clone(),
                errors: None,
            }),
            ApiError::Conflict(msg) => HttpResponse::Conflict().json(ErrorResponse {
                success: false,
                message: msg.clone(),
                errors: None,
            }),
            ApiError::InternalServerError(msg) => {
                HttpResponse::InternalServerError().json(ErrorResponse {
                    success: false,
                    message: msg.clone(),
                    errors: None,
                })
            }
            ApiError::ValidationError(errors) => HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                message: "Validation failed".to_string(),
                errors: Some(errors.clone()),
            }),
        }
    }
}

impl From<mongodb::error::Error> for ApiError {
    fn from(err: mongodb::error::Error) -> Self {
        ApiError::InternalServerError(err.to_string())
    }
}

impl From<bcrypt::BcryptError> for ApiError {
    fn from(err: bcrypt::BcryptError) -> Self {
        ApiError::InternalServerError(err.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for ApiError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        ApiError::Unauthorized(err.to_string())
    }
}

