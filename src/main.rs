mod apps;
mod core;

use crate::core::db;
use crate::core::openapi::configure_api_docs;
use actix_web::dev::ServiceRequest;
use actix_web::{
    App, HttpResponse, HttpServer, dev::fn_service, get, http::header, middleware::Logger, web,
};
use dotenvy::dotenv;
use serde_json::json;

/// Root page handler
#[get("/")]
async fn root() -> HttpResponse {
    // Return HTML response for the root page
    let html_content = r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Welcome to KlarID API</title>
            
        </head>
        <body>
            <div class="container">
                <h1>Welcome to KlarID API</h1>
                <p>Here are some useful links:</p>
                <ul>
                    <li><a href="/swagger">Swagger UI</a></li>
                    <li><a href="/redoc">ReDoc</a></li>
                </ul>
            </div>
        </body>
        </html>
    "#;

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html_content)
}

/// 404 page handler
async fn not_found() -> HttpResponse {
    // Return JSON response for unmatched routes
    HttpResponse::NotFound().json(json!({
        "error": "Not Found"
    }))
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Set RUST_LOG environment variable safely
    if std::env::var("RUST_LOG").is_err() {
        unsafe {
            std::env::set_var("RUST_LOG", "debug");
        }
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
            // Register root page route
            .service(root)
            // Configure routes using the route modules
            .configure(crate::apps::users::routers::user_routes)
            .configure(crate::apps::auth::routers::auth_routes)
            .configure(crate::apps::health::routers::health_routes)
            // Add default service to handle trailing slashes and 404
            .default_service(fn_service(|req: ServiceRequest| async move {
                let path = req.path().to_owned();

                // Skip redirect if path already ends with a slash, is empty, or is a file
                if path.ends_with('/') || path.is_empty() || path.contains('.') {
                    // Await the async not_found handler before converting into response
                    let resp = not_found().await;
                    return Ok(req.into_response(resp));
                }

                // Create redirect URL with trailing slash
                let mut redirect_url = format!("{}/", path);

                // Preserve query string if present
                let query = req.query_string();
                if !query.is_empty() {
                    redirect_url = format!("{}?{}", redirect_url, query);
                }

                // Return permanent redirect response
                Ok(req.into_response(
                    HttpResponse::PermanentRedirect()
                        .insert_header((header::LOCATION, redirect_url))
                        .finish(),
                ))
            }))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
