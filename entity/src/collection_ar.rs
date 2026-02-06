//! `SeaORM` Entity, generated for collection_ar

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Deserialize, Serialize)]
#[sea_orm(table_name = "collection_ar")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub title: String,
    pub description: Option<String>,
    pub is_public: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::collection_ar_subjects::Entity")]
    CollectionArSubjects,
    #[sea_orm(has_many = "super::collection_ar_accessions::Entity")]
    CollectionArAccessions,
}

impl Related<super::collection_ar_subjects::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CollectionArSubjects.def()
    }
}

impl Related<super::collection_ar_accessions::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CollectionArAccessions.def()
    }
}

impl Related<super::dublin_metadata_subject_ar::Entity> for Entity {
    fn to() -> RelationDef {
        super::collection_ar_subjects::Relation::DublinMetadataSubjectAr.def()
    }
    fn via() -> Option<RelationDef> {
        Some(
            super::collection_ar_subjects::Relation::CollectionAr
                .def()
                .rev(),
        )
    }
}

impl Related<super::accession::Entity> for Entity {
    fn to() -> RelationDef {
        super::collection_ar_accessions::Relation::Accession.def()
    }
    fn via() -> Option<RelationDef> {
        Some(
            super::collection_ar_accessions::Relation::CollectionAr
                .def()
                .rev(),
        )
    }
}

impl ActiveModelBehavior for ActiveModel {}
