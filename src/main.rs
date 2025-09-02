mod apps;
mod core;

use actix_web::{web, App, HttpServer, middleware::Logger, HttpResponse, http::header, dev::fn_service};
use actix_web::dev::ServiceRequest;
use futures::future::ok;
use dotenvy::dotenv;
use crate::core::openapi::configure_api_docs;
use crate::core::db;


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
            // Add middleware for logging
            .wrap(Logger::default())
            // Configure API documentation (Swagger UI and ReDoc)
            .configure(configure_api_docs)

            // Configure routes using the route modules
            .configure(crate::apps::users::routers::user_routes)
            .configure(crate::apps::auth::routers::auth_routes)
            .configure(crate::apps::health::routers::health_routes)
            
            // Add default service to handle trailing slashes
            .default_service(fn_service(|req: ServiceRequest| {
                let path = req.path().to_owned();
                
                // Skip if path already ends with a slash or is the root path
                if path.ends_with('/') || path == "" || path.contains('.') {
                    return ok(req.into_response(
                        HttpResponse::NotFound().finish()
                    ));
                }
                
                // Create redirect URL with trailing slash
                let redirect_url = format!("{}/", path);
                
                // Add query string if present
                let query = req.query_string();
                let redirect_url = if !query.is_empty() {
                    format!("{}?{}", redirect_url, query)
                } else {
                    redirect_url
                };
                
                // Return permanent redirect response
                ok(req.into_response(
                    HttpResponse::PermanentRedirect()
                        .insert_header((header::LOCATION, redirect_url))
                        .finish()
                ))
            }))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
