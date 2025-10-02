use crate::apps::auth::handlers::{
    __path_login, __path_logout, __path_refresh_token, __path_register,
};
use crate::apps::auth::handlers::{login, logout, refresh_token, register};
use actix_web::web;
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(paths(register, login, refresh_token, logout,))]
pub struct AuthApiDoc;

pub fn auth_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .route("/register/", web::post().to(register))
            .route("/login/", web::post().to(login))
            .route("/refresh/", web::post().to(refresh_token))
            .route("/logout/", web::post().to(logout)),
    );
}
