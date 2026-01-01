use actix_web::{HttpResponse, ResponseError};
use serde::Serialize;
use std::fmt;

use crate::constants::{CODE_BAD_REQUEST, CODE_INTERNAL_ERROR};

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub success: bool,
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
}

#[derive(Debug)]
pub enum ApiError {
    BadRequest { code: String, message: String },
    Unauthorized { code: String, message: String },
    NotFound { code: String, message: String },
    Conflict { code: String, message: String },
    InternalServerError { code: String, message: String },
    ValidationError { code: String, errors: Vec<String> },
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::BadRequest { code, message } => {
                write!(f, "Bad Request [{}]: {}", code, message)
            }
            ApiError::Unauthorized { code, message } => {
                write!(f, "Unauthorized [{}]: {}", code, message)
            }
            ApiError::NotFound { code, message } => {
                write!(f, "Not Found [{}]: {}", code, message)
            }
            ApiError::Conflict { code, message } => {
                write!(f, "Conflict [{}]: {}", code, message)
            }
            ApiError::InternalServerError { code, message } => {
                write!(f, "Internal Server Error [{}]: {}", code, message)
            }
            ApiError::ValidationError { code, errors } => {
                write!(f, "Validation Error [{}]: {:?}", code, errors)
            }
        }
    }
}

impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ApiError::BadRequest { code, message } => {
                HttpResponse::BadRequest().json(ErrorResponse {
                    success: false,
                    code: code.clone(),
                    message: message.clone(),
                    errors: None,
                })
            }
            ApiError::Unauthorized { code, message } => {
                HttpResponse::Unauthorized().json(ErrorResponse {
                    success: false,
                    code: code.clone(),
                    message: message.clone(),
                    errors: None,
                })
            }
            ApiError::NotFound { code, message } => HttpResponse::NotFound().json(ErrorResponse {
                success: false,
                code: code.clone(),
                message: message.clone(),
                errors: None,
            }),
            ApiError::Conflict { code, message } => HttpResponse::Conflict().json(ErrorResponse {
                success: false,
                code: code.clone(),
                message: message.clone(),
                errors: None,
            }),
            ApiError::InternalServerError { code, message } => HttpResponse::InternalServerError()
                .json(ErrorResponse {
                    success: false,
                    code: code.clone(),
                    message: message.clone(),
                    errors: None,
                }),
            ApiError::ValidationError { code, errors } => {
                HttpResponse::BadRequest().json(ErrorResponse {
                    success: false,
                    code: code.clone(),
                    message: "Validation failed".to_string(),
                    errors: Some(errors.clone()),
                })
            }
        }
    }
}

impl From<mongodb::error::Error> for ApiError {
    fn from(err: mongodb::error::Error) -> Self {
        ApiError::InternalServerError {
            code: CODE_INTERNAL_ERROR.to_string(),
            message: err.to_string(),
        }
    }
}

impl From<bcrypt::BcryptError> for ApiError {
    fn from(err: bcrypt::BcryptError) -> Self {
        ApiError::InternalServerError {
            code: CODE_INTERNAL_ERROR.to_string(),
            message: err.to_string(),
        }
    }
}

impl From<jsonwebtoken::errors::Error> for ApiError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        ApiError::Unauthorized {
            code: CODE_BAD_REQUEST.to_string(),
            message: err.to_string(),
        }
    }
}
