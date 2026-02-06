//! `SeaORM` Entity, generated for collection_ar_accessions

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Deserialize, Serialize)]
#[sea_orm(table_name = "collection_ar_accessions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub collection_ar_id: i32,
    #[sea_orm(primary_key, auto_increment = false)]
    pub accession_id: i32,
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
        belongs_to = "super::accession::Entity",
        from = "Column::AccessionId",
        to = "super::accession::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    Accession,
}

impl Related<super::collection_ar::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CollectionAr.def()
    }
}

impl Related<super::accession::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Accession.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
