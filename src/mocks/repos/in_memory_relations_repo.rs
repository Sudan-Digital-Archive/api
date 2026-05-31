use crate::models::common::MetadataLanguage;
use crate::repos::relations_repo::RelationsRepo;
use async_trait::async_trait;
use sea_orm::DbErr;

#[derive(Clone, Debug, Default)]
pub struct InMemoryRelationsRepo {}

#[async_trait]
impl RelationsRepo for InMemoryRelationsRepo {
    async fn write_one(
        &self,
        _metadata_id: i32,
        _relation_type: entity::sea_orm_active_enums::DublinMetadataRelationType,
        _related_accession_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<crate::models::response::RelationResponse, DbErr> {
        Ok(crate::models::response::RelationResponse {
            id: 1,
            relation_type: "has_part".to_string(),
            related_accession_id: 2,
        })
    }

    async fn list(
        &self,
        _metadata_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Vec<crate::models::response::RelationResponse>, DbErr> {
        Ok(vec![crate::models::response::RelationResponse {
            id: 1,
            relation_type: "has_part".to_string(),
            related_accession_id: 2,
        }])
    }

    async fn get_one(
        &self,
        relation_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Option<crate::models::response::RelationResponse>, DbErr> {
        Ok(Some(crate::models::response::RelationResponse {
            id: relation_id,
            relation_type: "has_part".to_string(),
            related_accession_id: 2,
        }))
    }

    async fn delete_one(
        &self,
        _relation_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Option<()>, DbErr> {
        Ok(Some(()))
    }

    async fn verify_related_accessions_exist(
        &self,
        _related_accession_ids: Vec<i32>,
    ) -> Result<bool, DbErr> {
        Ok(true)
    }
}
