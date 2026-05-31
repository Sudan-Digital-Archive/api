use crate::models::common::MetadataLanguage;
use crate::repos::contributors_repo::ContributorsRepo;
use async_trait::async_trait;
use entity::dublin_metadata_contributor_ar::Model as DublinMetadataContributorArModel;
use entity::dublin_metadata_contributor_en::Model as DublinMetadataContributorEnModel;
use sea_orm::DbErr;

#[derive(Clone, Debug, Default)]
pub struct InMemoryContributorsRepo {}

#[async_trait]
impl ContributorsRepo for InMemoryContributorsRepo {
    async fn write_one(
        &self,
        create_contributor_request: crate::models::request::CreateContributorRequest,
    ) -> Result<crate::models::response::ContributorResponse, DbErr> {
        Ok(crate::models::response::ContributorResponse {
            id: 1,
            contributor: create_contributor_request.contributor,
        })
    }

    async fn list_paginated_ar(
        &self,
        _page: u64,
        _per_page: u64,
        _query_term: Option<String>,
        _collection_id: Option<i32>,
    ) -> Result<(Vec<DublinMetadataContributorArModel>, u64), DbErr> {
        Ok((
            vec![DublinMetadataContributorArModel {
                id: 1,
                contributor: "مختبر".to_string(),
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
    ) -> Result<(Vec<DublinMetadataContributorEnModel>, u64), DbErr> {
        Ok((
            vec![DublinMetadataContributorEnModel {
                id: 1,
                contributor: "Test Contributor".to_string(),
            }],
            10,
        ))
    }

    async fn verify_contributors_exist(
        &self,
        _contributor_ids: Vec<i32>,
        _metadata_language: MetadataLanguage,
    ) -> Result<bool, DbErr> {
        Ok(true)
    }

    async fn update_one(
        &self,
        _contributor_id: i32,
        update_contributor_request: crate::models::request::UpdateContributorRequest,
    ) -> Result<Option<crate::models::response::ContributorResponse>, DbErr> {
        Ok(Some(crate::models::response::ContributorResponse {
            id: 1,
            contributor: update_contributor_request.contributor,
        }))
    }

    async fn delete_one(
        &self,
        _contributor_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Option<()>, DbErr> {
        Ok(Some(()))
    }

    async fn get_one(
        &self,
        _contributor_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Option<crate::models::response::ContributorResponse>, DbErr> {
        Ok(Some(crate::models::response::ContributorResponse {
            id: 1,
            contributor: "Test Contributor".to_string(),
        }))
    }
}
