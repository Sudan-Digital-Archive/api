//! Repository module for managing contributor metadata in the digital archive.
//!
//! This module provides functionality for creating and listing contributor terms
//! that can be used to describe contributors to archived content in both Arabic and English.

use crate::models::common::MetadataLanguage;
use crate::models::request::{CreateContributorRequest, UpdateContributorRequest};
use crate::models::response::ContributorResponse;
use ::entity::dublin_metadata_contributor_ar::ActiveModel as DublinMetadataContributorArActiveModel;
use ::entity::dublin_metadata_contributor_ar::Entity as DublinMetadataContributorAr;
use ::entity::dublin_metadata_contributor_ar::Model as DublinMetadataContributorArModel;
use ::entity::dublin_metadata_contributor_en::ActiveModel as DublinMetadataContributorEnActiveModel;
use ::entity::dublin_metadata_contributor_en::Entity as DublinMetadataContributorEn;
use ::entity::dublin_metadata_contributor_en::Model as DublinMetadataContributorEnModel;
use async_trait::async_trait;
use entity::{dublin_metadata_contributor_ar, dublin_metadata_contributor_en};
use sea_orm::prelude::Expr;
use sea_orm::sea_query::{ExprTrait, Func};
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, DatabaseConnection, DbErr, EntityTrait,
    IntoActiveModel, PaginatorTrait, QueryFilter,
};
use std::collections::HashSet;

/// Repository implementation for database operations on contributors.
#[derive(Debug, Clone, Default)]
pub struct DBContributorsRepo {
    pub db_session: DatabaseConnection,
}

/// Defines the interface for contributor-related database operations.
///
/// This trait provides methods for creating and retrieving contributor terms
/// that can be used to describe contributors to archived content in both Arabic and English.
#[async_trait]
pub trait ContributorsRepo: Send + Sync {
    /// Creates a new contributor term in the specified language.
    ///
    /// # Arguments
    /// * `create_contributor_request` - The request containing contributor details and language
    async fn write_one(
        &self,
        create_contributor_request: CreateContributorRequest,
    ) -> Result<ContributorResponse, DbErr>;

    /// Lists Arabic contributor terms with pagination and optional text search.
    ///
    /// # Arguments
    /// * `page` - The page number to retrieve
    /// * `per_page` - Number of records per page
    /// * `query_term` - Optional text search term
    async fn list_paginated_ar(
        &self,
        page: u64,
        per_page: u64,
        query_term: Option<String>,
    ) -> Result<(Vec<DublinMetadataContributorArModel>, u64), DbErr>;

    /// Lists English contributor terms with pagination and optional text search.
    ///
    /// # Arguments
    /// * `page` - The page number to retrieve
    /// * `per_page` - Number of records per page
    /// * `query_term` - Optional text search term
    async fn list_paginated_en(
        &self,
        page: u64,
        per_page: u64,
        query_term: Option<String>,
    ) -> Result<(Vec<DublinMetadataContributorEnModel>, u64), DbErr>;

    /// Verifies that all provided contributor IDs exist in the database.
    ///
    /// # Arguments
    /// * `contributor_ids` - List of contributor IDs to verify
    /// * `metadata_language` - Language of the contributors to check
    async fn verify_contributors_exist(
        &self,
        contributor_ids: Vec<i32>,
        metadata_language: MetadataLanguage,
    ) -> Result<bool, DbErr>;

    /// Updates a contributor term by its ID.
    ///
    /// # Arguments
    /// * `contributor_id` - The ID of the contributor to update.
    /// * `update_contributor_request` - The update request containing new contributor text and language
    async fn update_one(
        &self,
        contributor_id: i32,
        update_contributor_request: UpdateContributorRequest,
    ) -> Result<Option<ContributorResponse>, DbErr>;

    /// Deletes a contributor term by its ID.
    ///
    /// # Arguments
    /// * `contributor_id` - The ID of the contributor to delete.
    /// * `metadata_language` - Language of the contributor to delete
    async fn delete_one(
        &self,
        contributor_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<()>, DbErr>;

    /// Retrieves a single contributor term by its ID.
    ///
    /// # Arguments
    /// * `contributor_id` - The ID of the contributor to retrieve.
    /// * `metadata_language` - Language of the contributor to retrieve
    async fn get_one(
        &self,
        contributor_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<ContributorResponse>, DbErr>;
}

#[async_trait]
impl ContributorsRepo for DBContributorsRepo {
    async fn write_one(
        &self,
        create_contributor_request: CreateContributorRequest,
    ) -> Result<ContributorResponse, DbErr> {
        let resp = match create_contributor_request.lang {
            MetadataLanguage::English => {
                let contributor = DublinMetadataContributorEnActiveModel {
                    id: Default::default(),
                    contributor: ActiveValue::Set(create_contributor_request.contributor),
                };
                let new_contributor = contributor.insert(&self.db_session).await?;
                ContributorResponse {
                    id: new_contributor.id,
                    contributor: new_contributor.contributor,
                }
            }
            MetadataLanguage::Arabic => {
                let contributor = DublinMetadataContributorArActiveModel {
                    id: Default::default(),
                    contributor: ActiveValue::Set(create_contributor_request.contributor),
                };
                let new_contributor = contributor.insert(&self.db_session).await?;
                ContributorResponse {
                    id: new_contributor.id,
                    contributor: new_contributor.contributor,
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
    ) -> Result<(Vec<DublinMetadataContributorArModel>, u64), DbErr> {
        let mut query = DublinMetadataContributorAr::find();

        if let Some(term) = query_term {
            let query_string = format!("%{}%", term.to_lowercase());
            let query_filter = Func::lower(Expr::col(
                dublin_metadata_contributor_ar::Column::Contributor,
            ))
            .like(&query_string);
            query = query.filter(query_filter);
        }

        let contributor_pages = query.paginate(&self.db_session, per_page);
        let num_pages = contributor_pages.num_pages().await?;
        Ok((contributor_pages.fetch_page(page).await?, num_pages))
    }

    async fn list_paginated_en(
        &self,
        page: u64,
        per_page: u64,
        query_term: Option<String>,
    ) -> Result<(Vec<DublinMetadataContributorEnModel>, u64), DbErr> {
        let mut query = DublinMetadataContributorEn::find();

        if let Some(term) = query_term {
            let query_string = format!("%{}%", term.to_lowercase());
            let query_filter = Func::lower(Expr::col(
                dublin_metadata_contributor_en::Column::Contributor,
            ))
            .like(&query_string);
            query = query.filter(query_filter);
        }

        let contributor_pages = query.paginate(&self.db_session, per_page);
        let num_pages = contributor_pages.num_pages().await?;
        Ok((contributor_pages.fetch_page(page).await?, num_pages))
    }

    async fn verify_contributors_exist(
        &self,
        contributor_ids: Vec<i32>,
        metadata_language: MetadataLanguage,
    ) -> Result<bool, DbErr> {
        let input_set: HashSet<i32> = contributor_ids.iter().cloned().collect();
        let flag = match metadata_language {
            MetadataLanguage::English => {
                let rows = DublinMetadataContributorEn::find()
                    .filter(
                        dublin_metadata_contributor_en::Column::Id.is_in(contributor_ids.clone()),
                    )
                    .all(&self.db_session)
                    .await?;
                let found_set: HashSet<i32> = rows.iter().map(|r| r.id).collect();
                input_set == found_set
            }
            MetadataLanguage::Arabic => {
                let rows = DublinMetadataContributorAr::find()
                    .filter(
                        dublin_metadata_contributor_ar::Column::Id.is_in(contributor_ids.clone()),
                    )
                    .all(&self.db_session)
                    .await?;
                let found_set: HashSet<i32> = rows.iter().map(|r| r.id).collect();
                input_set == found_set
            }
        };
        Ok(flag)
    }

    async fn update_one(
        &self,
        contributor_id: i32,
        update_contributor_request: UpdateContributorRequest,
    ) -> Result<Option<ContributorResponse>, DbErr> {
        let result = match update_contributor_request.lang {
            MetadataLanguage::English => {
                let contributor = DublinMetadataContributorEn::find_by_id(contributor_id)
                    .one(&self.db_session)
                    .await?;
                if let Some(existing_contributor) = contributor {
                    let mut active_contributor = existing_contributor.into_active_model();
                    active_contributor.contributor =
                        ActiveValue::Set(update_contributor_request.contributor);
                    let updated_contributor = active_contributor.update(&self.db_session).await?;
                    Some(ContributorResponse {
                        id: updated_contributor.id,
                        contributor: updated_contributor.contributor,
                    })
                } else {
                    None
                }
            }
            MetadataLanguage::Arabic => {
                let contributor = DublinMetadataContributorAr::find_by_id(contributor_id)
                    .one(&self.db_session)
                    .await?;
                if let Some(existing_contributor) = contributor {
                    let mut active_contributor = existing_contributor.into_active_model();
                    active_contributor.contributor =
                        ActiveValue::Set(update_contributor_request.contributor);
                    let updated_contributor = active_contributor.update(&self.db_session).await?;
                    Some(ContributorResponse {
                        id: updated_contributor.id,
                        contributor: updated_contributor.contributor,
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
        contributor_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<()>, DbErr> {
        let deletion = match metadata_language {
            MetadataLanguage::English => {
                DublinMetadataContributorEn::delete_by_id(contributor_id)
                    .exec(&self.db_session)
                    .await?
            }
            MetadataLanguage::Arabic => {
                DublinMetadataContributorAr::delete_by_id(contributor_id)
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
        contributor_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<ContributorResponse>, DbErr> {
        let result = match metadata_language {
            MetadataLanguage::English => {
                let contributor = DublinMetadataContributorEn::find_by_id(contributor_id)
                    .one(&self.db_session)
                    .await?;
                contributor.map(|c| ContributorResponse {
                    id: c.id,
                    contributor: c.contributor,
                })
            }
            MetadataLanguage::Arabic => {
                let contributor = DublinMetadataContributorAr::find_by_id(contributor_id)
                    .one(&self.db_session)
                    .await?;
                contributor.map(|c| ContributorResponse {
                    id: c.id,
                    contributor: c.contributor,
                })
            }
        };
        Ok(result)
    }
}
