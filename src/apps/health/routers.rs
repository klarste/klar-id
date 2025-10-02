use super::handlers::health_check;
use crate::apps::health::handlers::__path_health_check;
use actix_web::web;
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(paths(health_check,))]
pub struct HealthApiDoc;

pub fn health_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/health").route("/", web::get().to(health_check)));
}
