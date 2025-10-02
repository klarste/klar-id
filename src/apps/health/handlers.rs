use actix_web::{HttpResponse, Responder};

/// Health check
#[utoipa::path(
    get,
    path = "/",
    responses((status = 200, description = "Health check OK"))
)]
pub async fn health_check() -> impl Responder {
    HttpResponse::Ok().body("OK")
}
