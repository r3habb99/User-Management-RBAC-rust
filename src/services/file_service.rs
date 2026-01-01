//! File service for handling file upload and deletion operations.

use actix_multipart::Multipart;
use futures::StreamExt;
use log::warn;
use std::io::Write;
use std::path::PathBuf;
use uuid::Uuid;

use crate::config::CONFIG;
use crate::constants::{
    CODE_FILE_UPLOAD_FAILED, CODE_INTERNAL_ERROR, ERR_FAILED_PROCESS_UPLOAD, ERR_FAILED_READ_FILE,
    ERR_FAILED_SAVE_FILE, ERR_NO_AVATAR_FILE,
};
use crate::errors::ApiError;
use crate::validators::{
    get_extension_from_content_type, validate_avatar_content_type, validate_avatar_size,
};

/// Service for file operations (upload, deletion).
pub struct FileService {
    upload_dir: PathBuf,
}

impl FileService {
    /// Create a new FileService instance using the default upload directory from config.
    pub fn new() -> Self {
        Self {
            upload_dir: PathBuf::from(&CONFIG.upload_dir),
        }
    }

    /// Create a new FileService with a custom upload directory.
    #[allow(dead_code)]
    pub fn with_upload_dir(upload_dir: PathBuf) -> Self {
        Self { upload_dir }
    }

    /// Save an avatar file from a multipart upload.
    ///
    /// Processes the multipart payload, validates the file type and size,
    /// and saves the file to the upload directory.
    ///
    /// Returns the URL path to the saved avatar (e.g., "/uploads/filename.jpg").
    pub async fn save_avatar(
        &self,
        user_id: &str,
        payload: &mut Multipart,
    ) -> Result<String, ApiError> {
        while let Some(item) = payload.next().await {
            let mut field = item.map_err(|e| {
                warn!("Failed to process multipart field: {}", e);
                ApiError::BadRequest {
                    code: CODE_FILE_UPLOAD_FAILED.to_string(),
                    message: ERR_FAILED_PROCESS_UPLOAD.to_string(),
                }
            })?;

            // Get content disposition
            let content_disposition = field.content_disposition();
            let field_name = content_disposition
                .map(|cd| cd.get_name().unwrap_or(""))
                .unwrap_or("");

            if field_name != "avatar" {
                continue;
            }

            // Validate content type
            let content_type = field.content_type().map(|ct| ct.to_string());
            validate_avatar_content_type(content_type.as_deref())?;

            // Generate unique filename
            let extension = get_extension_from_content_type(content_type.as_deref());
            let filename = format!("{}_{}.{}", user_id, Uuid::new_v4(), extension);

            // Create upload directory if it doesn't exist
            if !self.upload_dir.exists() {
                std::fs::create_dir_all(&self.upload_dir).map_err(|e| {
                    warn!("Failed to create upload directory: {}", e);
                    ApiError::InternalServerError {
                        code: CODE_INTERNAL_ERROR.to_string(),
                        message: ERR_FAILED_SAVE_FILE.to_string(),
                    }
                })?;
            }

            let filepath = self.upload_dir.join(&filename);

            // Create the file
            let mut file = std::fs::File::create(&filepath).map_err(|e| {
                warn!("Failed to create file: {}", e);
                ApiError::InternalServerError {
                    code: CODE_INTERNAL_ERROR.to_string(),
                    message: ERR_FAILED_SAVE_FILE.to_string(),
                }
            })?;

            // Write the file content with size limit
            let mut total_size: usize = 0;

            while let Some(chunk) = field.next().await {
                let data = chunk.map_err(|e| {
                    warn!("Failed to read chunk: {}", e);
                    ApiError::BadRequest {
                        code: CODE_FILE_UPLOAD_FAILED.to_string(),
                        message: ERR_FAILED_READ_FILE.to_string(),
                    }
                })?;

                total_size += data.len();
                if let Err(e) = validate_avatar_size(total_size) {
                    // Clean up the partial file
                    let _ = std::fs::remove_file(&filepath);
                    return Err(e);
                }

                file.write_all(&data).map_err(|e| {
                    warn!("Failed to write file: {}", e);
                    ApiError::InternalServerError {
                        code: CODE_INTERNAL_ERROR.to_string(),
                        message: ERR_FAILED_SAVE_FILE.to_string(),
                    }
                })?;
            }

            return Ok(format!("/uploads/{}", filename));
        }

        Err(ApiError::BadRequest {
            code: CODE_FILE_UPLOAD_FAILED.to_string(),
            message: ERR_NO_AVATAR_FILE.to_string(),
        })
    }

    /// Delete a file from the upload directory.
    ///
    /// The file_path should be in the format "/uploads/filename.ext".
    /// Silently ignores if the file doesn't exist.
    pub fn delete_file(&self, file_path: &str) -> Result<(), ApiError> {
        if file_path.starts_with("/uploads/") {
            let filename = file_path.trim_start_matches("/uploads/");
            let filepath = self.upload_dir.join(filename);
            if filepath.exists() {
                let _ = std::fs::remove_file(&filepath);
            }
        }
        Ok(())
    }
}

impl Default for FileService {
    fn default() -> Self {
        Self::new()
    }
}
