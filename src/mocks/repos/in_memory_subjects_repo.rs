use crate::models::common::MetadataLanguage;
use crate::repos::subjects_repo::SubjectsRepo;
use async_trait::async_trait;
use entity::dublin_metadata_subject_ar::Model as DublinMetadataSubjectArModel;
use entity::dublin_metadata_subject_en::Model as DublinMetadataSubjectEnModel;
use sea_orm::DbErr;

#[derive(Clone, Debug, Default)]
pub struct InMemorySubjectsRepo {}

#[async_trait]
impl SubjectsRepo for InMemorySubjectsRepo {
    async fn write_one(
        &self,
        _create_subject_request: crate::models::request::CreateSubjectRequest,
    ) -> Result<crate::models::response::SubjectResponse, DbErr> {
        Ok(crate::models::response::SubjectResponse {
            id: 1,
            subject: "some cool archive".to_string(),
        })
    }

    async fn delete_one(
        &self,
        _subject_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Option<()>, DbErr> {
        Ok(Some(()))
    }

    async fn list_paginated_ar(
        &self,
        _page: u64,
        _per_page: u64,
        _query_term: Option<String>,
        _collection_id: Option<i32>,
    ) -> Result<(Vec<DublinMetadataSubjectArModel>, u64), DbErr> {
        Ok(mock_paginated_subjects_ar())
    }

    async fn list_paginated_en(
        &self,
        _page: u64,
        _per_page: u64,
        _query_term: Option<String>,
        _collection_id: Option<i32>,
    ) -> Result<(Vec<DublinMetadataSubjectEnModel>, u64), DbErr> {
        Ok(mock_paginated_subjects_en())
    }

    async fn update_one(
        &self,
        _subject_id: i32,
        _update_subject_request: crate::models::request::UpdateSubjectRequest,
    ) -> Result<Option<crate::models::response::SubjectResponse>, DbErr> {
        Ok(Some(crate::models::response::SubjectResponse {
            id: 1,
            subject: "updated subject".to_string(),
        }))
    }

    async fn verify_subjects_exist(
        &self,
        _subject_ids: Vec<i32>,
        _metadata_language: MetadataLanguage,
    ) -> Result<bool, DbErr> {
        Ok(true)
    }

    async fn get_one(
        &self,
        subject_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Option<crate::models::response::SubjectResponse>, DbErr> {
        Ok(Some(crate::models::response::SubjectResponse {
            id: subject_id,
            subject: "Mock Subject".to_string(),
        }))
    }
}

fn mock_paginated_subjects_en() -> (Vec<DublinMetadataSubjectEnModel>, u64) {
    (
        vec![DublinMetadataSubjectEnModel {
            id: 1,
            subject: "English Subject".to_string(),
        }],
        10,
    )
}

fn mock_paginated_subjects_ar() -> (Vec<DublinMetadataSubjectArModel>, u64) {
    (
        vec![DublinMetadataSubjectArModel {
            id: 1,
            subject: "Arabic Subject".to_string(),
        }],
        10,
    )
}
