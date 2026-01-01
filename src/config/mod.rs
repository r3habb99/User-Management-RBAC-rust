use std::env;

use lazy_static::lazy_static;

lazy_static! {
    pub static ref CONFIG: Config = Config::from_env();
}

#[derive(Debug, Clone)]
pub struct Config {
    pub server_host: String,
    pub server_port: u16,
    pub mongodb_uri: String,
    pub database_name: String,
    pub jwt_secret: String,
    pub jwt_expiration_hours: i64,
    pub upload_dir: String,
    // Admin seeding configuration
    pub admin_email: String,
    pub admin_username: String,
    pub admin_password: String,
    pub seed_admin: bool,
    // CORS configuration
    pub cors_origins: Vec<String>,
}

impl Config {
    pub fn from_env() -> Self {
        dotenv::dotenv().ok();

        Self {
            server_host: env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            server_port: env::var("SERVER_PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .expect("SERVER_PORT must be a valid number"),
            mongodb_uri: env::var("MONGODB_URI")
                .unwrap_or_else(|_| "mongodb://localhost:27017".to_string()),
            database_name: env::var("DATABASE_NAME")
                .unwrap_or_else(|_| "user_management".to_string()),
            jwt_secret: env::var("JWT_SECRET")
                .unwrap_or_else(|_| "your-super-secret-jwt-key-change-in-production".to_string()),
            jwt_expiration_hours: env::var("JWT_EXPIRATION_HOURS")
                .unwrap_or_else(|_| "24".to_string())
                .parse()
                .expect("JWT_EXPIRATION_HOURS must be a valid number"),
            upload_dir: env::var("UPLOAD_DIR").unwrap_or_else(|_| "./uploads".to_string()),
            // Admin seeding configuration
            admin_email: env::var("ADMIN_EMAIL").unwrap_or_else(|_| "admin@test.com".to_string()),
            admin_username: env::var("ADMIN_USERNAME").unwrap_or_else(|_| "admin".to_string()),
            admin_password: env::var("ADMIN_PASSWORD").unwrap_or_else(|_| "Admin@2026".to_string()),
            seed_admin: env::var("SEED_ADMIN")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
            // CORS origins (comma-separated list)
            cors_origins: env::var("CORS_ORIGINS")
                .unwrap_or_else(|_| "http://127.0.0.1:8080,http://localhost:8080".to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        }
    }
}
