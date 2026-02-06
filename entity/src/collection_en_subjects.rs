//! `SeaORM` Entity, generated for collection_en_subjects

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Deserialize, Serialize)]
#[sea_orm(table_name = "collection_en_subjects")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub collection_en_id: i32,
    #[sea_orm(primary_key, auto_increment = false)]
    pub subject_en_id: i32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::collection_en::Entity",
        from = "Column::CollectionEnId",
        to = "super::collection_en::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    CollectionEn,
    #[sea_orm(
        belongs_to = "super::dublin_metadata_subject_en::Entity",
        from = "Column::SubjectEnId",
        to = "super::dublin_metadata_subject_en::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    DublinMetadataSubjectEn,
}

impl Related<super::collection_en::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CollectionEn.def()
    }
}

impl Related<super::dublin_metadata_subject_en::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::DublinMetadataSubjectEn.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
