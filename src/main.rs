mod config;
mod errors;
mod handlers;
mod middleware;
mod models;
mod routes;
mod services;

use actix_web::{middleware::Logger, web, App, HttpServer};
use log::info;
use mongodb::Client;

use crate::config::CONFIG;
use crate::services::UserService;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize environment variables and logger
    dotenv::dotenv().ok();
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    // Connect to MongoDB
    info!("Connecting to MongoDB...");
    let client = Client::with_uri_str(&CONFIG.mongodb_uri)
        .await
        .expect("Failed to connect to MongoDB");

    let db = client.database(&CONFIG.database_name);

    // Test MongoDB connection
    db.run_command(bson::doc! { "ping": 1 }, None)
        .await
        .expect("Failed to ping MongoDB");
    info!("Connected to MongoDB successfully!");

    // Initialize services
    let user_service = web::Data::new(UserService::new(&db));

    // Start HTTP server
    let server_addr = format!("{}:{}", CONFIG.server_host, CONFIG.server_port);
    info!("Starting server at http://{}", server_addr);

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(user_service.clone())
            .configure(routes::configure_routes)
    })
    .bind(&server_addr)?
    .run()
    .await
}
