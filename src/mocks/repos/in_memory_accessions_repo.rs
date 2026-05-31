use crate::models::accessions::AccessionError;
use crate::models::common::MetadataLanguage;
use crate::models::request::{
    AccessionPaginationWithPrivate, CreateAccessionRequest, CreateAccessionRequestRaw,
};
use crate::repos::accessions_repo::AccessionsRepo;
use async_trait::async_trait;
use entity::accession::Model as AccessionModel;
use entity::accessions_with_metadata::Model as AccessionsWithMetadataModel;
use entity::sea_orm_active_enums::CrawlStatus;
use sea_orm::DbErr;
use uuid::Uuid;

#[derive(Clone, Debug, Default)]
pub struct InMemoryAccessionsRepo {}

#[async_trait]
impl AccessionsRepo for InMemoryAccessionsRepo {
    async fn write_one(
        &self,
        _create_accession_request: CreateAccessionRequest,
        _org_id: Uuid,
        _crawl_id: Uuid,
        _job_run_id: String,
        _crawl_status: CrawlStatus,
        _s3_filename: String,
    ) -> Result<i32, DbErr> {
        Ok(10)
    }

    async fn write_one_raw(
        &self,
        _create_accession_request: CreateAccessionRequestRaw,
        _s3_filename: String,
    ) -> Result<i32, DbErr> {
        Ok(10)
    }

    async fn get_one(
        &self,
        _id: i32,
        _private: bool,
    ) -> Result<Option<AccessionsWithMetadataModel>, DbErr> {
        Ok(Some(mock_one_accession_with_metadata()))
    }

    async fn list_paginated(
        &self,
        _params: AccessionPaginationWithPrivate,
    ) -> Result<(Vec<AccessionsWithMetadataModel>, u64), DbErr> {
        Ok(mock_paginated_en())
    }

    async fn delete_one(&self, _id: i32) -> Result<Option<AccessionModel>, AccessionError> {
        Ok(Some(mock_one_accession()))
    }

    async fn update_one(
        &self,
        _id: i32,
        _update_accession_request: crate::models::request::UpdateAccessionRequest,
    ) -> Result<Option<i32>, DbErr> {
        Ok(Some(_id))
    }

    async fn get_dublin_metadata_id(
        &self,
        _accession_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Option<i32>, DbErr> {
        Ok(Some(1))
    }

    async fn has_incoming_relations(&self, _id: i32) -> Result<bool, AccessionError> {
        Ok(false)
    }
}

fn mock_paginated_en() -> (Vec<AccessionsWithMetadataModel>, u64) {
    (vec![mock_one_accession_with_metadata()], 10)
}

fn mock_one_accession_with_metadata() -> AccessionsWithMetadataModel {
    use serde_json::json;
    AccessionsWithMetadataModel {
        id: 1,
        crawl_status: CrawlStatus::Complete,
        crawl_timestamp: Default::default(),
        crawl_id: Some(Default::default()),
        org_id: Some(Default::default()),
        job_run_id: Some("some_job_id".to_string()),
        dublin_metadata_date: Default::default(),
        has_arabic_metadata: true,
        has_english_metadata: true,
        title_en: Some("English Title".to_string()),
        description_en: Some("English Description".to_string()),
        location_en: Some("English Location".to_string()),
        location_en_id: Some(1),
        creator_en_id: Some(1),
        creator_en: Some("English Creator".to_string()),
        title_ar: Some("Arabic Title".to_string()),
        description_ar: Some("Arabic Description".to_string()),
        location_ar: Some("Arabic Location".to_string()),
        location_ar_id: Some(2),
        creator_ar_id: Some(2),
        creator_ar: Some("Arabic Creator".to_string()),
        subjects_en: Some(vec!["archive".to_string()]),
        subjects_ar: Some(vec!["mrhaba archive".to_string()]),
        seed_url: "https://example.com".to_string(),
        subjects_en_ids: Some(vec![1]),
        subjects_ar_ids: Some(vec![3]),
        is_private: true,
        dublin_metadata_format: entity::sea_orm_active_enums::DublinMetadataFormat::Wacz,
        s3_filename: Some("some_file.wacz".to_string()),
        contributors_en: Some(vec!["Paul McCartney".to_string()]),
        contributor_en_ids: Some(vec![1]),
        contributor_roles_en: Some(vec!["singer".to_string()]),
        contributor_role_en_ids: Some(vec![1]),
        contributors_ar: Some(vec!["بول ماك كارتني".to_string()]),
        contributor_ar_ids: Some(vec![2]),
        contributor_roles_ar: Some(vec!["مغني".to_string()]),
        contributor_role_ar_ids: Some(vec![2]),
        relations_en: Some(
            json!([{"id": 1, "relation_type": "has_part", "related_accession_id": 2}]),
        ),
        relations_ar: Some(
            json!([{"id": 2, "relation_type": "is_part_of", "related_accession_id": 3}]),
        ),
    }
}

fn mock_one_accession() -> AccessionModel {
    AccessionModel {
        id: 1,
        dublin_metadata_en: Some(1),
        dublin_metadata_ar: Some(2),
        crawl_status: CrawlStatus::Complete,
        crawl_timestamp: Default::default(),
        dublin_metadata_date: Default::default(),
        crawl_id: Some(Default::default()),
        org_id: Some(Default::default()),
        job_run_id: Some("some_job_id".to_string()),
        seed_url: "https://example.com".to_string(),
        is_private: true,
        dublin_metadata_format: entity::sea_orm_active_enums::DublinMetadataFormat::Wacz,
        s3_filename: Some("some_file.wacz".to_string()),
    }
}
