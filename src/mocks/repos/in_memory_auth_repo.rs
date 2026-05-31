use crate::models::request::AuthorizeRequest;
use crate::repos::auth_repo::{ApiKeyUserInfo, AuthRepo};
use async_trait::async_trait;
use entity::sea_orm_active_enums::Role;
use sea_orm::DbErr;
use uuid::Uuid;

#[derive(Clone, Debug, Default)]
pub struct InMemoryAuthRepo {}

#[async_trait]
impl AuthRepo for InMemoryAuthRepo {
    async fn get_user_by_email(&self, _email: String) -> Result<Option<Uuid>, DbErr> {
        Ok(Some(Uuid::new_v4()))
    }

    async fn create_session(&self, _user_id: Uuid) -> Result<Uuid, DbErr> {
        Ok(Uuid::new_v4())
    }

    async fn delete_expired_sessions(&self) {}

    async fn get_session_expiry(
        &self,
        _authorize_request: AuthorizeRequest,
    ) -> Result<Option<chrono::NaiveDateTime>, DbErr> {
        Ok(Some(chrono::NaiveDateTime::default()))
    }

    async fn get_one(&self, _user_id: Uuid) -> Result<Option<entity::archive_user::Model>, DbErr> {
        Ok(Some(entity::archive_user::Model {
            id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            role: entity::sea_orm_active_enums::Role::Admin,
            is_active: true,
        }))
    }

    async fn create_api_key_for_user(&self, _user_id: Uuid) -> Result<String, DbErr> {
        Ok("mock_api_key_secret".to_string())
    }

    async fn verify_api_key(&self, _api_key: String) -> Result<Option<ApiKeyUserInfo>, DbErr> {
        Ok(Some(ApiKeyUserInfo {
            user_id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            role: Role::Admin,
        }))
    }

    async fn delete_expired_api_keys(&self) {}

    async fn create_user(
        &self,
        email: String,
        role: entity::sea_orm_active_enums::Role,
        is_active: bool,
    ) -> Result<entity::archive_user::Model, DbErr> {
        Ok(entity::archive_user::Model {
            id: Uuid::new_v4(),
            email,
            role,
            is_active,
        })
    }

    async fn update_user(
        &self,
        user_id: Uuid,
        role: entity::sea_orm_active_enums::Role,
        is_active: bool,
    ) -> Result<Option<entity::archive_user::Model>, DbErr> {
        Ok(Some(entity::archive_user::Model {
            id: user_id,
            email: "updated@example.com".to_string(),
            role,
            is_active,
        }))
    }

    async fn get_user_by_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<entity::archive_user::Model>, DbErr> {
        Ok(Some(entity::archive_user::Model {
            id: user_id,
            email: "test@example.com".to_string(),
            role: entity::sea_orm_active_enums::Role::Researcher,
            is_active: true,
        }))
    }

    async fn list_users(
        &self,
        _page: u64,
        _per_page: u64,
        _email_filter: Option<String>,
    ) -> Result<(Vec<entity::archive_user::Model>, u64), DbErr> {
        Ok((
            vec![entity::archive_user::Model {
                id: Uuid::new_v4(),
                email: "test@example.com".to_string(),
                role: entity::sea_orm_active_enums::Role::Researcher,
                is_active: true,
            }],
            1,
        ))
    }

    async fn delete_user(&self, _user_id: Uuid) -> Result<Option<()>, DbErr> {
        Ok(Some(()))
    }

    async fn revoke_api_key(&self, _key_hash: String, _user_id: Uuid) -> Result<Option<()>, DbErr> {
        Ok(Some(()))
    }
}
