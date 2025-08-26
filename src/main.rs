mod users;
mod auth;
mod db;
mod health;
mod openapi;

use actix_web::{web, App, HttpServer};
use dotenvy::dotenv;
use openapi::configure_api_docs;


#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Set RUST_LOG environment variable safely
    if std::env::var("RUST_LOG").is_err() {
        unsafe { std::env::set_var("RUST_LOG", "debug"); }
    }
    env_logger::init();

    // Load environment variables from .env
    dotenv().ok();

    // Connect to database
    let db_pool = db::create_pool()
        .await
        .expect("Failed to create database pool");
    
    // Create web::Data for the database pool
    let db_data = web::Data::new(db_pool);

    HttpServer::new(move || {
        App::new()
            // Add database pool to app data
            .app_data(db_data.clone())
            // Configure API documentation (Swagger UI and ReDoc)
            .configure(configure_api_docs)

            // Configure routes using the route modules
            .configure(users::routers::user_routes)
            .configure(auth::routers::auth_routes)
            .configure(health::health_routes)


    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
