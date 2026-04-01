//! Repository module for managing relation metadata in the digital archive.

use crate::models::common::MetadataLanguage;
use crate::models::response::RelationResponse;
use async_trait::async_trait;
use entity::accession::Column as AccessionColumn;
use entity::accession::Entity as Accession;
use entity::dublin_metadata_ar_relations::ActiveModel as DublinMetadataArRelationsActiveModel;
use entity::dublin_metadata_ar_relations::Column as DublinMetadataArRelationsColumn;
use entity::dublin_metadata_ar_relations::Entity as DublinMetadataArRelations;
use entity::dublin_metadata_en_relations::ActiveModel as DublinMetadataEnRelationsActiveModel;
use entity::dublin_metadata_en_relations::Column as DublinMetadataEnRelationsColumn;
use entity::dublin_metadata_en_relations::Entity as DublinMetadataEnRelations;
use entity::dublin_metadata_relation_ar::ActiveModel as DublinMetadataRelationArActiveModel;
use entity::dublin_metadata_relation_ar::Entity as DublinMetadataRelationAr;
use entity::dublin_metadata_relation_ar::Relation as DublinMetadataRelationArRelation;
use entity::dublin_metadata_relation_en::ActiveModel as DublinMetadataRelationEnActiveModel;
use entity::dublin_metadata_relation_en::Entity as DublinMetadataRelationEn;
use entity::dublin_metadata_relation_en::Relation as DublinMetadataRelationEnRelation;
use entity::sea_orm_active_enums::DublinMetadataRelationType;
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, DatabaseConnection, DbErr, EntityTrait, JoinType,
    QueryFilter, QuerySelect, RelationTrait, TransactionTrait,
};

fn relation_type_to_string(rt: DublinMetadataRelationType) -> String {
    match rt {
        DublinMetadataRelationType::HasPart => "has_part".to_string(),
        DublinMetadataRelationType::IsPartOf => "is_part_of".to_string(),
        DublinMetadataRelationType::HasVersion => "has_version".to_string(),
        DublinMetadataRelationType::IsVersionOf => "is_version_of".to_string(),
        DublinMetadataRelationType::References => "references".to_string(),
        DublinMetadataRelationType::IsReferencedBy => "is_referenced_by".to_string(),
        DublinMetadataRelationType::ConformsTo => "conforms_to".to_string(),
        DublinMetadataRelationType::Requires => "requires".to_string(),
    }
}

#[derive(Debug, Clone, Default)]
pub struct DBRelationsRepo {
    pub db_session: DatabaseConnection,
}

#[async_trait]
pub trait RelationsRepo: Send + Sync {
    async fn write_one(
        &self,
        metadata_id: i32,
        relation_type: DublinMetadataRelationType,
        related_accession_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<RelationResponse, DbErr>;

    async fn list(
        &self,
        metadata_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Vec<RelationResponse>, DbErr>;

    async fn get_one(
        &self,
        relation_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<RelationResponse>, DbErr>;

    async fn delete_one(
        &self,
        relation_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<()>, DbErr>;

    async fn verify_related_accessions_exist(
        &self,
        related_accession_ids: Vec<i32>,
    ) -> Result<bool, DbErr>;
}

#[async_trait]
impl RelationsRepo for DBRelationsRepo {
    async fn write_one(
        &self,
        metadata_id: i32,
        relation_type: DublinMetadataRelationType,
        related_accession_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<RelationResponse, DbErr> {
        let txn = self.db_session.begin().await?;

        let response = match metadata_language {
            MetadataLanguage::English => {
                let relation = DublinMetadataRelationEnActiveModel {
                    id: Default::default(),
                    relation_type: ActiveValue::Set(relation_type),
                    related_accession_id: ActiveValue::Set(related_accession_id),
                };
                let new_relation = relation.insert(&txn).await?;

                let link = DublinMetadataEnRelationsActiveModel {
                    metadata_id: ActiveValue::Set(metadata_id),
                    relation_id: ActiveValue::Set(new_relation.id),
                };
                link.insert(&txn).await?;

                RelationResponse {
                    id: new_relation.id,
                    relation_type: match new_relation.relation_type {
                        DublinMetadataRelationType::HasPart => "has_part".to_string(),
                        DublinMetadataRelationType::IsPartOf => "is_part_of".to_string(),
                        DublinMetadataRelationType::HasVersion => "has_version".to_string(),
                        DublinMetadataRelationType::IsVersionOf => "is_version_of".to_string(),
                        DublinMetadataRelationType::References => "references".to_string(),
                        DublinMetadataRelationType::IsReferencedBy => {
                            "is_referenced_by".to_string()
                        }
                        DublinMetadataRelationType::ConformsTo => "conforms_to".to_string(),
                        DublinMetadataRelationType::Requires => "requires".to_string(),
                    },
                    related_accession_id: new_relation.related_accession_id,
                }
            }
            MetadataLanguage::Arabic => {
                let relation = DublinMetadataRelationArActiveModel {
                    id: Default::default(),
                    relation_type: ActiveValue::Set(relation_type),
                    related_accession_id: ActiveValue::Set(related_accession_id),
                };
                let new_relation = relation.insert(&txn).await?;

                let link = DublinMetadataArRelationsActiveModel {
                    metadata_id: ActiveValue::Set(metadata_id),
                    relation_id: ActiveValue::Set(new_relation.id),
                };
                link.insert(&txn).await?;

                RelationResponse {
                    id: new_relation.id,
                    relation_type: match new_relation.relation_type {
                        DublinMetadataRelationType::HasPart => "has_part".to_string(),
                        DublinMetadataRelationType::IsPartOf => "is_part_of".to_string(),
                        DublinMetadataRelationType::HasVersion => "has_version".to_string(),
                        DublinMetadataRelationType::IsVersionOf => "is_version_of".to_string(),
                        DublinMetadataRelationType::References => "references".to_string(),
                        DublinMetadataRelationType::IsReferencedBy => {
                            "is_referenced_by".to_string()
                        }
                        DublinMetadataRelationType::ConformsTo => "conforms_to".to_string(),
                        DublinMetadataRelationType::Requires => "requires".to_string(),
                    },
                    related_accession_id: new_relation.related_accession_id,
                }
            }
        };

        txn.commit().await?;
        Ok(response)
    }

    async fn list(
        &self,
        metadata_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Vec<RelationResponse>, DbErr> {
        match metadata_language {
            MetadataLanguage::English => {
                let relations = DublinMetadataRelationEn::find()
                    .join(
                        JoinType::InnerJoin,
                        DublinMetadataRelationEnRelation::DublinMetadataEnRelations.def(),
                    )
                    .filter(DublinMetadataEnRelationsColumn::MetadataId.eq(metadata_id))
                    .all(&self.db_session)
                    .await?;
                Ok(relations
                    .into_iter()
                    .map(|r| RelationResponse {
                        id: r.id,
                        relation_type: relation_type_to_string(r.relation_type),
                        related_accession_id: r.related_accession_id,
                    })
                    .collect())
            }
            MetadataLanguage::Arabic => {
                let relations = DublinMetadataRelationAr::find()
                    .join(
                        JoinType::InnerJoin,
                        DublinMetadataRelationArRelation::DublinMetadataArRelations.def(),
                    )
                    .filter(DublinMetadataArRelationsColumn::MetadataId.eq(metadata_id))
                    .all(&self.db_session)
                    .await?;
                Ok(relations
                    .into_iter()
                    .map(|r| RelationResponse {
                        id: r.id,
                        relation_type: relation_type_to_string(r.relation_type),
                        related_accession_id: r.related_accession_id,
                    })
                    .collect())
            }
        }
    }

    async fn get_one(
        &self,
        relation_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<RelationResponse>, DbErr> {
        let result = match metadata_language {
            MetadataLanguage::English => {
                let relation = DublinMetadataRelationEn::find_by_id(relation_id)
                    .one(&self.db_session)
                    .await?;
                relation.map(|r| RelationResponse {
                    id: r.id,
                    relation_type: relation_type_to_string(r.relation_type),
                    related_accession_id: r.related_accession_id,
                })
            }
            MetadataLanguage::Arabic => {
                let relation = DublinMetadataRelationAr::find_by_id(relation_id)
                    .one(&self.db_session)
                    .await?;
                relation.map(|r| RelationResponse {
                    id: r.id,
                    relation_type: relation_type_to_string(r.relation_type),
                    related_accession_id: r.related_accession_id,
                })
            }
        };
        Ok(result)
    }

    async fn delete_one(
        &self,
        relation_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<()>, DbErr> {
        let txn = self.db_session.begin().await?;

        let deleted = match metadata_language {
            MetadataLanguage::English => {
                let link_deleted = DublinMetadataEnRelations::delete_many()
                    .filter(DublinMetadataEnRelationsColumn::RelationId.eq(relation_id))
                    .exec(&txn)
                    .await?;
                if link_deleted.rows_affected > 0 {
                    let relation_deleted = DublinMetadataRelationEn::delete_by_id(relation_id)
                        .exec(&txn)
                        .await?;
                    relation_deleted.rows_affected > 0
                } else {
                    false
                }
            }
            MetadataLanguage::Arabic => {
                let link_deleted = DublinMetadataArRelations::delete_many()
                    .filter(DublinMetadataArRelationsColumn::RelationId.eq(relation_id))
                    .exec(&txn)
                    .await?;
                if link_deleted.rows_affected > 0 {
                    let relation_deleted = DublinMetadataRelationAr::delete_by_id(relation_id)
                        .exec(&txn)
                        .await?;
                    relation_deleted.rows_affected > 0
                } else {
                    false
                }
            }
        };

        txn.commit().await?;
        if deleted {
            Ok(Some(()))
        } else {
            Ok(None)
        }
    }

    async fn verify_related_accessions_exist(
        &self,
        related_accession_ids: Vec<i32>,
    ) -> Result<bool, DbErr> {
        let rows = Accession::find()
            .filter(AccessionColumn::Id.is_in(related_accession_ids.clone()))
            .all(&self.db_session)
            .await?;
        Ok(rows.len() == related_accession_ids.len())
    }
}
