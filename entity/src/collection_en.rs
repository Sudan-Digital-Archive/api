//! `SeaORM` Entity, generated for collection_en

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Deserialize, Serialize)]
#[sea_orm(table_name = "collection_en")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub title: String,
    pub description: Option<String>,
    pub is_public: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::collection_en_subjects::Entity")]
    CollectionEnSubjects,
    #[sea_orm(has_many = "super::collection_en_accessions::Entity")]
    CollectionEnAccessions,
}

impl Related<super::collection_en_subjects::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CollectionEnSubjects.def()
    }
}

impl Related<super::collection_en_accessions::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CollectionEnAccessions.def()
    }
}

impl Related<super::dublin_metadata_subject_en::Entity> for Entity {
    fn to() -> RelationDef {
        super::collection_en_subjects::Relation::DublinMetadataSubjectEn.def()
    }
    fn via() -> Option<RelationDef> {
        Some(
            super::collection_en_subjects::Relation::CollectionEn
                .def()
                .rev(),
        )
    }
}

impl Related<super::accession::Entity> for Entity {
    fn to() -> RelationDef {
        super::collection_en_accessions::Relation::Accession.def()
    }
    fn via() -> Option<RelationDef> {
        Some(
            super::collection_en_accessions::Relation::CollectionEn
                .def()
                .rev(),
        )
    }
}

impl ActiveModelBehavior for ActiveModel {}
