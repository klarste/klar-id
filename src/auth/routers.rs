use actix_web::web;
use utoipa::OpenApi;
use crate::auth::handlers::{register, login, refresh_token, logout};
use crate::auth::handlers::{
    __path_register,
    __path_login,
    __path_refresh_token,
    __path_logout
};

#[derive(OpenApi)]
#[openapi(paths(
    register,
    login,
    refresh_token,
    logout,
))]
pub struct AuthApiDoc;

pub fn auth_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .route("/register/", web::post().to(register))
            .route("/login/", web::post().to(login))
            .route("/refresh/", web::post().to(refresh_token))
            .route("/logout/", web::post().to(logout))
    );
}