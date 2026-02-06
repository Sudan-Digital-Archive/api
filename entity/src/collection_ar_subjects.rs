//! `SeaORM` Entity, generated for collection_ar_subjects

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Deserialize, Serialize)]
#[sea_orm(table_name = "collection_ar_subjects")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub collection_ar_id: i32,
    #[sea_orm(primary_key, auto_increment = false)]
    pub subject_ar_id: i32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::collection_ar::Entity",
        from = "Column::CollectionArId",
        to = "super::collection_ar::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    CollectionAr,
    #[sea_orm(
        belongs_to = "super::dublin_metadata_subject_ar::Entity",
        from = "Column::SubjectArId",
        to = "super::dublin_metadata_subject_ar::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    DublinMetadataSubjectAr,
}

impl Related<super::collection_ar::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CollectionAr.def()
    }
}

impl Related<super::dublin_metadata_subject_ar::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::DublinMetadataSubjectAr.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
