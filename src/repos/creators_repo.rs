//! Repository module for managing creator metadata in the digital archive.
//!
//! This module provides functionality for creating and listing creator terms
//! that can be used to categorize archived content in both Arabic and English.

use crate::models::common::MetadataLanguage;
use crate::models::request::{CreateCreatorRequest, UpdateCreatorRequest};
use crate::models::response::CreatorResponse;
use ::entity::dublin_metadata_creator_ar::ActiveModel as DublinMetadataCreatorArActiveModel;
use ::entity::dublin_metadata_creator_ar::Entity as DublinMetadataCreatorAr;
use ::entity::dublin_metadata_creator_ar::Model as DublinMetadataCreatorArModel;
use ::entity::dublin_metadata_creator_en::ActiveModel as DublinMetadataCreatorEnActiveModel;
use ::entity::dublin_metadata_creator_en::Entity as DublinMetadataCreatorEn;
use ::entity::dublin_metadata_creator_en::Model as DublinMetadataCreatorEnModel;
use async_trait::async_trait;
use sea_orm::prelude::Expr;
use sea_orm::sea_query::{ExprTrait, Func};
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, DatabaseConnection, DbErr, EntityTrait,
    IntoActiveModel, PaginatorTrait, QueryFilter,
};

#[derive(Debug, Clone, Default)]
pub struct DBCreatorsRepo {
    pub db_session: DatabaseConnection,
}

#[async_trait]
pub trait CreatorsRepo: Send + Sync {
    async fn write_one(
        &self,
        create_creator_request: CreateCreatorRequest,
    ) -> Result<CreatorResponse, DbErr>;

    async fn list_paginated_ar(
        &self,
        page: u64,
        per_page: u64,
        query_term: Option<String>,
    ) -> Result<(Vec<DublinMetadataCreatorArModel>, u64), DbErr>;

    async fn list_paginated_en(
        &self,
        page: u64,
        per_page: u64,
        query_term: Option<String>,
    ) -> Result<(Vec<DublinMetadataCreatorEnModel>, u64), DbErr>;

    #[allow(dead_code)]
    async fn verify_creators_exist(
        &self,
        creator_ids: Vec<i32>,
        metadata_language: MetadataLanguage,
    ) -> Result<bool, DbErr>;

    async fn update_one(
        &self,
        creator_id: i32,
        update_creator_request: UpdateCreatorRequest,
    ) -> Result<Option<CreatorResponse>, DbErr>;

    async fn delete_one(
        &self,
        creator_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<()>, DbErr>;

    async fn get_one(
        &self,
        creator_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<CreatorResponse>, DbErr>;
}

#[async_trait]
impl CreatorsRepo for DBCreatorsRepo {
    async fn write_one(
        &self,
        create_creator_request: CreateCreatorRequest,
    ) -> Result<CreatorResponse, DbErr> {
        let resp = match create_creator_request.lang {
            MetadataLanguage::English => {
                let creator = DublinMetadataCreatorEnActiveModel {
                    id: Default::default(),
                    creator: ActiveValue::Set(create_creator_request.creator),
                };
                let new_creator = creator.insert(&self.db_session).await?;
                CreatorResponse {
                    id: new_creator.id,
                    creator: new_creator.creator,
                }
            }
            MetadataLanguage::Arabic => {
                let creator = DublinMetadataCreatorArActiveModel {
                    id: Default::default(),
                    creator: ActiveValue::Set(create_creator_request.creator),
                };
                let new_creator = creator.insert(&self.db_session).await?;
                CreatorResponse {
                    id: new_creator.id,
                    creator: new_creator.creator,
                }
            }
        };
        Ok(resp)
    }

    async fn list_paginated_ar(
        &self,
        page: u64,
        per_page: u64,
        query_term: Option<String>,
    ) -> Result<(Vec<DublinMetadataCreatorArModel>, u64), DbErr> {
        let mut query = DublinMetadataCreatorAr::find();

        if let Some(term) = query_term {
            let query_string = format!("%{}%", term.to_lowercase());
            let query_filter = Func::lower(Expr::col(
                ::entity::dublin_metadata_creator_ar::Column::Creator,
            ))
            .like(&query_string);
            query = query.filter(query_filter);
        }

        let creator_pages = query.paginate(&self.db_session, per_page);
        let num_pages = creator_pages.num_pages().await?;
        Ok((creator_pages.fetch_page(page).await?, num_pages))
    }

    async fn list_paginated_en(
        &self,
        page: u64,
        per_page: u64,
        query_term: Option<String>,
    ) -> Result<(Vec<DublinMetadataCreatorEnModel>, u64), DbErr> {
        let mut query = DublinMetadataCreatorEn::find();

        if let Some(term) = query_term {
            let query_string = format!("%{}%", term.to_lowercase());
            let query_filter = Func::lower(Expr::col(
                ::entity::dublin_metadata_creator_en::Column::Creator,
            ))
            .like(&query_string);
            query = query.filter(query_filter);
        }

        let creator_pages = query.paginate(&self.db_session, per_page);
        let num_pages = creator_pages.num_pages().await?;
        Ok((creator_pages.fetch_page(page).await?, num_pages))
    }

    async fn verify_creators_exist(
        &self,
        creator_ids: Vec<i32>,
        metadata_language: MetadataLanguage,
    ) -> Result<bool, DbErr> {
        let flag = match metadata_language {
            MetadataLanguage::English => {
                let rows: Vec<DublinMetadataCreatorEnModel> = DublinMetadataCreatorEn::find()
                    .filter(
                        ::entity::dublin_metadata_creator_en::Column::Id.is_in(creator_ids.clone()),
                    )
                    .all(&self.db_session)
                    .await?;
                rows.len() == creator_ids.len()
            }
            MetadataLanguage::Arabic => {
                let rows: Vec<DublinMetadataCreatorArModel> = DublinMetadataCreatorAr::find()
                    .filter(
                        ::entity::dublin_metadata_creator_ar::Column::Id.is_in(creator_ids.clone()),
                    )
                    .all(&self.db_session)
                    .await?;
                rows.len() == creator_ids.len()
            }
        };
        Ok(flag)
    }

    async fn update_one(
        &self,
        creator_id: i32,
        update_creator_request: UpdateCreatorRequest,
    ) -> Result<Option<CreatorResponse>, DbErr> {
        let result = match update_creator_request.lang {
            MetadataLanguage::English => {
                let creator = DublinMetadataCreatorEn::find_by_id(creator_id)
                    .one(&self.db_session)
                    .await?;
                if let Some(existing_creator) = creator {
                    let mut active_creator = existing_creator.into_active_model();
                    active_creator.creator = ActiveValue::Set(update_creator_request.creator);
                    let updated_creator = active_creator.update(&self.db_session).await?;
                    Some(CreatorResponse {
                        id: updated_creator.id,
                        creator: updated_creator.creator,
                    })
                } else {
                    None
                }
            }
            MetadataLanguage::Arabic => {
                let creator = DublinMetadataCreatorAr::find_by_id(creator_id)
                    .one(&self.db_session)
                    .await?;
                if let Some(existing_creator) = creator {
                    let mut active_creator = existing_creator.into_active_model();
                    active_creator.creator = ActiveValue::Set(update_creator_request.creator);
                    let updated_creator = active_creator.update(&self.db_session).await?;
                    Some(CreatorResponse {
                        id: updated_creator.id,
                        creator: updated_creator.creator,
                    })
                } else {
                    None
                }
            }
        };
        Ok(result)
    }

    async fn delete_one(
        &self,
        creator_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<()>, DbErr> {
        let deletion = match metadata_language {
            MetadataLanguage::English => {
                DublinMetadataCreatorEn::delete_by_id(creator_id)
                    .exec(&self.db_session)
                    .await?
            }
            MetadataLanguage::Arabic => {
                DublinMetadataCreatorAr::delete_by_id(creator_id)
                    .exec(&self.db_session)
                    .await?
            }
        };
        if deletion.rows_affected > 0 {
            Ok(Some(()))
        } else {
            Ok(None)
        }
    }

    async fn get_one(
        &self,
        creator_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<CreatorResponse>, DbErr> {
        let result = match metadata_language {
            MetadataLanguage::English => {
                let creator = DublinMetadataCreatorEn::find_by_id(creator_id)
                    .one(&self.db_session)
                    .await?;
                creator.map(|s| CreatorResponse {
                    id: s.id,
                    creator: s.creator,
                })
            }
            MetadataLanguage::Arabic => {
                let creator = DublinMetadataCreatorAr::find_by_id(creator_id)
                    .one(&self.db_session)
                    .await?;
                creator.map(|s| CreatorResponse {
                    id: s.id,
                    creator: s.creator,
                })
            }
        };
        Ok(result)
    }
}
