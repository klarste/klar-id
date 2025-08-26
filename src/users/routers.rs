use actix_web::web;
use utoipa::OpenApi;
use crate::users::handlers::{create_user, get_user, list_users, update_user, delete_user};
use crate::users::handlers::{__path_create_user, __path_get_user, __path_list_users, __path_update_user, __path_delete_user};

#[derive(OpenApi)]
#[openapi(paths(
    create_user,
    list_users,
    get_user,
    update_user,
    delete_user
))]
pub struct UsersApiDoc;

pub fn user_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .route("/", web::post().to(create_user))
            .route("/", web::get().to(list_users))
            .route("/{user_id}/", web::get().to(get_user))
            .route("/{user_id}/", web::patch().to(update_user))
            .route("/{user_id}/", web::delete().to(delete_user))
    );
}