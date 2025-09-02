use serde::{Deserialize, Serialize};
// use svix_ksuid::{Ksuid, KsuidLike};
use chrono::{DateTime, Utc};
use utoipa::ToSchema;
use crate::apps::users::models::KsuidSchema;

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct RefreshToken {
    pub id: KsuidSchema,
    pub user_id: KsuidSchema,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

// impl RefreshToken {
//     pub fn new(user_id: KsuidSchema, token: String, expires_at: DateTime<Utc>) -> Self {
//         Self {
//             id: KsuidSchema(Ksuid::new(None, None)),
//             user_id,
//             token,
//             expires_at,
//             created_at: Utc::now(),
//         }
//     }
// }