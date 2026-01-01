mod config;
mod errors;
mod handlers;
mod middleware;
mod models;
mod openapi;
mod routes;
mod services;

use actix_files::Files;
use actix_web::{middleware::Logger, web, App, HttpServer};
use log::info;
use mongodb::Client;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::config::CONFIG;
use crate::openapi::ApiDoc;
use crate::services::UserService;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize environment variables and logger
    dotenv::dotenv().ok();
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    // Create uploads directory if it doesn't exist
    let upload_dir = &CONFIG.upload_dir;
    if !std::path::Path::new(upload_dir).exists() {
        std::fs::create_dir_all(upload_dir).expect("Failed to create uploads directory");
        info!("Created uploads directory: {}", upload_dir);
    }

    // Connect to MongoDB
    info!("Connecting to MongoDB...");
    let client = Client::with_uri_str(&CONFIG.mongodb_uri)
        .await
        .expect("Failed to connect to MongoDB");

    let db = client.database(&CONFIG.database_name);

    // Test MongoDB connection
    db.run_command(mongodb::bson::doc! { "ping": 1 })
        .await
        .expect("Failed to ping MongoDB");
    info!("Connected to MongoDB successfully!");

    // Initialize services
    let user_service = web::Data::new(UserService::new(&db));

    // Clone upload_dir for use in HttpServer closure
    let upload_dir_clone = upload_dir.clone();

    // Start HTTP server
    let server_addr = format!("{}:{}", CONFIG.server_host, CONFIG.server_port);
    info!("Starting server at http://{}", server_addr);

    // Generate OpenAPI spec
    let openapi = ApiDoc::openapi();

    info!("Swagger UI available at http://{}/swagger-ui/", server_addr);

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(user_service.clone())
            .configure(routes::configure_routes)
            // Swagger UI
            .service(
                SwaggerUi::new("/swagger-ui/{_:.*}").url("/api-docs/openapi.json", openapi.clone()),
            )
            // Serve uploaded files
            .service(Files::new("/uploads", &upload_dir_clone).show_files_listing())
    })
    .bind(&server_addr)?
    .run()
    .await
}
