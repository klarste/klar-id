use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use utoipa_redoc::Redoc;
use utoipa_redoc::Servable;
use crate::auth;
use crate::users;
use crate::health;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Blaze Auth API",
        version = "1.0.0",
        description = "API documentation for Blaze Auth service"
    ),
    nest(
        (path = "/health", api = health::HealthApiDoc),
        (path = "/auth", api = auth::AuthApiDoc),
        (path = "/users", api = users::UsersApiDoc)
    )
)]
pub struct ApiDoc;

// Configure Swagger UI and ReDoc services
pub fn configure_api_docs(cfg: &mut actix_web::web::ServiceConfig) {
    cfg.service(
        SwaggerUi::new("/swagger/{_:.*}")
            .url("/openapi.json", ApiDoc::openapi()),
    )
    .service(
        Redoc::with_url("/redoc", ApiDoc::openapi())
    );
}