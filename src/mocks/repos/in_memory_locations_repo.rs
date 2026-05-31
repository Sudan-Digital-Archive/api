use crate::models::common::MetadataLanguage;
use crate::repos::locations_repo::LocationsRepo;
use async_trait::async_trait;
use entity::dublin_metadata_location_ar::Model as DublinMetadataLocationArModel;
use entity::dublin_metadata_location_en::Model as DublinMetadataLocationEnModel;
use sea_orm::DbErr;

#[derive(Clone, Debug, Default)]
pub struct InMemoryLocationsRepo {}

#[async_trait]
impl LocationsRepo for InMemoryLocationsRepo {
    async fn write_one(
        &self,
        create_location_request: crate::models::request::CreateLocationRequest,
    ) -> Result<crate::models::response::LocationResponse, DbErr> {
        let location = match create_location_request.lang {
            MetadataLanguage::English => "Khartoum".to_string(),
            MetadataLanguage::Arabic => "الخرطوم".to_string(),
        };
        Ok(crate::models::response::LocationResponse { id: 1, location })
    }

    async fn list_paginated_ar(
        &self,
        _page: u64,
        _per_page: u64,
        _query_term: Option<String>,
        _collection_id: Option<i32>,
    ) -> Result<(Vec<DublinMetadataLocationArModel>, u64), DbErr> {
        Ok((
            vec![DublinMetadataLocationArModel {
                id: 1,
                location: "الخرطوم".to_string(),
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
    ) -> Result<(Vec<DublinMetadataLocationEnModel>, u64), DbErr> {
        Ok((
            vec![DublinMetadataLocationEnModel {
                id: 1,
                location: "Khartoum".to_string(),
            }],
            10,
        ))
    }

    async fn verify_locations_exist(
        &self,
        _location_ids: Vec<i32>,
        _metadata_language: MetadataLanguage,
    ) -> Result<bool, DbErr> {
        Ok(true)
    }

    async fn update_one(
        &self,
        _location_id: i32,
        _update_location_request: crate::models::request::UpdateLocationRequest,
    ) -> Result<Option<crate::models::response::LocationResponse>, DbErr> {
        Ok(Some(crate::models::response::LocationResponse {
            id: 1,
            location: "updated location".to_string(),
        }))
    }

    async fn delete_one(
        &self,
        _location_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Option<()>, DbErr> {
        Ok(Some(()))
    }

    async fn get_one(
        &self,
        _location_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Option<crate::models::response::LocationResponse>, DbErr> {
        Ok(Some(crate::models::response::LocationResponse {
            id: 1,
            location: "Khartoum".to_string(),
        }))
    }
}
