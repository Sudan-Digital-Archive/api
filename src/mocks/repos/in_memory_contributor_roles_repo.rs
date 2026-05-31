use crate::models::common::MetadataLanguage;
use crate::repos::contributor_roles_repo::ContributorRolesRepo;
use async_trait::async_trait;
use entity::dublin_metadata_contributor_role_ar::Model as DublinMetadataContributorRoleArModel;
use entity::dublin_metadata_contributor_role_en::Model as DublinMetadataContributorRoleEnModel;
use sea_orm::DbErr;

#[derive(Clone, Debug, Default)]
pub struct InMemoryContributorRolesRepo {}

#[async_trait]
impl ContributorRolesRepo for InMemoryContributorRolesRepo {
    async fn write_one(
        &self,
        create_role_request: crate::models::request::CreateContributorRoleRequest,
    ) -> Result<crate::models::response::ContributorRoleResponse, DbErr> {
        Ok(crate::models::response::ContributorRoleResponse {
            id: 1,
            role: create_role_request.role,
        })
    }

    async fn list_paginated_ar(
        &self,
        _page: u64,
        _per_page: u64,
        _query_term: Option<String>,
        _collection_id: Option<i32>,
    ) -> Result<(Vec<DublinMetadataContributorRoleArModel>, u64), DbErr> {
        Ok((
            vec![DublinMetadataContributorRoleArModel {
                id: 1,
                role: "مختبر دور".to_string(),
            }],
            10,
        ))
    }

    async fn list_paginated_en(
        &self,
        _page: u64,
        _per_page: u64,
        _query_term: Option<String>,
        _collection_id: Option<i32>,
    ) -> Result<(Vec<DublinMetadataContributorRoleEnModel>, u64), DbErr> {
        Ok((
            vec![DublinMetadataContributorRoleEnModel {
                id: 1,
                role: "Test Role".to_string(),
            }],
            10,
        ))
    }

    async fn verify_roles_exist(
        &self,
        _role_ids: Vec<i32>,
        _metadata_language: MetadataLanguage,
    ) -> Result<bool, DbErr> {
        Ok(true)
    }

    async fn update_one(
        &self,
        _role_id: i32,
        update_role_request: crate::models::request::UpdateContributorRoleRequest,
    ) -> Result<Option<crate::models::response::ContributorRoleResponse>, DbErr> {
        Ok(Some(crate::models::response::ContributorRoleResponse {
            id: 1,
            role: update_role_request.role,
        }))
    }

    async fn delete_one(
        &self,
        _role_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Option<()>, DbErr> {
        Ok(Some(()))
    }

    async fn get_one(
        &self,
        _role_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Option<crate::models::response::ContributorRoleResponse>, DbErr> {
        Ok(Some(crate::models::response::ContributorRoleResponse {
            id: 1,
            role: "Test Role".to_string(),
        }))
    }
}
