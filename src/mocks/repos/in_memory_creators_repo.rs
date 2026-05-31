use crate::models::common::MetadataLanguage;
use crate::repos::creators_repo::CreatorsRepo;
use async_trait::async_trait;
use entity::dublin_metadata_creator_ar::Model as DublinMetadataCreatorArModel;
use entity::dublin_metadata_creator_en::Model as DublinMetadataCreatorEnModel;
use sea_orm::DbErr;

#[derive(Clone, Debug, Default)]
pub struct InMemoryCreatorsRepo {}

#[async_trait]
impl CreatorsRepo for InMemoryCreatorsRepo {
    async fn write_one(
        &self,
        create_creator_request: crate::models::request::CreateCreatorRequest,
    ) -> Result<crate::models::response::CreatorResponse, DbErr> {
        let creator = match create_creator_request.lang {
            MetadataLanguage::English => "Test Creator".to_string(),
            MetadataLanguage::Arabic => "مختبر".to_string(),
        };
        Ok(crate::models::response::CreatorResponse { id: 1, creator })
    }

    async fn list_paginated_ar(
        &self,
        _page: u64,
        _per_page: u64,
        _query_term: Option<String>,
        _collection_id: Option<i32>,
    ) -> Result<(Vec<DublinMetadataCreatorArModel>, u64), DbErr> {
        Ok((
            vec![DublinMetadataCreatorArModel {
                id: 1,
                creator: "مختبر".to_string(),
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
    ) -> Result<(Vec<DublinMetadataCreatorEnModel>, u64), DbErr> {
        Ok((
            vec![DublinMetadataCreatorEnModel {
                id: 1,
                creator: "Test Creator".to_string(),
            }],
            10,
        ))
    }

    async fn verify_creators_exist(
        &self,
        _creator_ids: Vec<i32>,
        _metadata_language: MetadataLanguage,
    ) -> Result<bool, DbErr> {
        Ok(true)
    }

    async fn update_one(
        &self,
        _creator_id: i32,
        _update_creator_request: crate::models::request::UpdateCreatorRequest,
    ) -> Result<Option<crate::models::response::CreatorResponse>, DbErr> {
        Ok(Some(crate::models::response::CreatorResponse {
            id: 1,
            creator: "updated creator".to_string(),
        }))
    }

    async fn delete_one(
        &self,
        _creator_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Option<()>, DbErr> {
        Ok(Some(()))
    }

    async fn get_one(
        &self,
        _creator_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Option<crate::models::response::CreatorResponse>, DbErr> {
        Ok(Some(crate::models::response::CreatorResponse {
            id: 1,
            creator: "Test Creator".to_string(),
        }))
    }
}
