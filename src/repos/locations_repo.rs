//! Repository module for managing location metadata in the digital archive.
//!
//! This module provides functionality for creating and listing location terms
//! that can be used to categorize archived content in both Arabic and English.

use crate::models::common::MetadataLanguage;
use crate::models::request::{CreateLocationRequest, UpdateLocationRequest};
use crate::models::response::LocationResponse;
use ::entity::collection_ar_subjects::Entity as CollectionArSubjects;
use ::entity::collection_en_subjects::Entity as CollectionEnSubjects;
use ::entity::dublin_metadata_ar_subjects::Entity as DublinMetadataArSubjects;
use ::entity::dublin_metadata_en_subjects::Entity as DublinMetadataEnSubjects;
use ::entity::dublin_metadata_location_ar::ActiveModel as DublinMetadataLocationArActiveModel;
use ::entity::dublin_metadata_location_ar::Entity as DublinMetadataLocationAr;
use ::entity::dublin_metadata_location_ar::Model as DublinMetadataLocationArModel;
use ::entity::dublin_metadata_location_en::ActiveModel as DublinMetadataLocationEnActiveModel;
use ::entity::dublin_metadata_location_en::Entity as DublinMetadataLocationEn;
use ::entity::dublin_metadata_location_en::Model as DublinMetadataLocationEnModel;
use async_trait::async_trait;
use entity::{
    collection_ar_subjects, collection_en_subjects, dublin_metadata_ar_subjects,
    dublin_metadata_en_subjects,
};
use sea_orm::prelude::Expr;
use sea_orm::sea_query::{ExprTrait, Func};
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, DatabaseConnection, DbErr, EntityTrait,
    IntoActiveModel, PaginatorTrait, QueryFilter,
};

/// Repository implementation for database operations on locations.
#[derive(Debug, Clone, Default)]
pub struct DBLocationsRepo {
    pub db_session: DatabaseConnection,
}

/// Defines the interface for location-related database operations.
#[async_trait]
pub trait LocationsRepo: Send + Sync {
    /// Creates a new location in the specified language.
    async fn write_one(
        &self,
        create_location_request: CreateLocationRequest,
    ) -> Result<LocationResponse, DbErr>;

    /// Lists Arabic locations with pagination and optional text search.
    async fn list_paginated_ar(
        &self,
        page: u64,
        per_page: u64,
        query_term: Option<String>,
        collection_id: Option<i32>,
    ) -> Result<(Vec<DublinMetadataLocationArModel>, u64), DbErr>;

    /// Lists English locations with pagination and optional text search.
    async fn list_paginated_en(
        &self,
        page: u64,
        per_page: u64,
        query_term: Option<String>,
        collection_id: Option<i32>,
    ) -> Result<(Vec<DublinMetadataLocationEnModel>, u64), DbErr>;

    /// Verifies that all provided location IDs exist in the database.
    async fn verify_locations_exist(
        &self,
        location_ids: Vec<i32>,
        metadata_language: MetadataLanguage,
    ) -> Result<bool, DbErr>;

    /// Updates a location by its ID.
    async fn update_one(
        &self,
        location_id: i32,
        update_location_request: UpdateLocationRequest,
    ) -> Result<Option<LocationResponse>, DbErr>;

    /// Deletes a location by its ID.
    async fn delete_one(
        &self,
        location_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<()>, DbErr>;

    /// Retrieves a single location by its ID.
    async fn get_one(
        &self,
        location_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<LocationResponse>, DbErr>;
}

#[async_trait]
impl LocationsRepo for DBLocationsRepo {
    async fn write_one(
        &self,
        create_location_request: CreateLocationRequest,
    ) -> Result<LocationResponse, DbErr> {
        let resp = match create_location_request.lang {
            MetadataLanguage::English => {
                let location = DublinMetadataLocationEnActiveModel {
                    id: Default::default(),
                    location: ActiveValue::Set(create_location_request.location),
                };
                let new_location = location.insert(&self.db_session).await?;
                LocationResponse {
                    id: new_location.id,
                    location: new_location.location,
                }
            }
            MetadataLanguage::Arabic => {
                let location = DublinMetadataLocationArActiveModel {
                    id: Default::default(),
                    location: ActiveValue::Set(create_location_request.location),
                };
                let new_location = location.insert(&self.db_session).await?;
                LocationResponse {
                    id: new_location.id,
                    location: new_location.location,
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
        collection_id: Option<i32>,
    ) -> Result<(Vec<DublinMetadataLocationArModel>, u64), DbErr> {
        let subject_ids: Vec<i32> = if let Some(coll_id) = collection_id {
            let collection_has_subjects = CollectionArSubjects::find()
                .filter(collection_ar_subjects::Column::CollectionArId.eq(coll_id))
                .count(&self.db_session)
                .await?;

            if collection_has_subjects == 0 {
                return Ok((Vec::new(), 0));
            }

            let subject_ids: Vec<i32> = CollectionArSubjects::find()
                .filter(collection_ar_subjects::Column::CollectionArId.eq(coll_id))
                .all(&self.db_session)
                .await?
                .into_iter()
                .map(|s| s.subject_ar_id)
                .collect();
            subject_ids
        } else {
            vec![]
        };

        let mut query = DublinMetadataLocationAr::find();

        if let Some(term) = query_term {
            let query_string = format!("%{}%", term.to_lowercase());
            let query_filter = Func::lower(Expr::col(
                entity::dublin_metadata_location_ar::Column::Location,
            ))
            .like(&query_string);
            query = query.filter(query_filter);
        }

        if !subject_ids.is_empty() {
            let metadata_ids: Vec<i32> = DublinMetadataArSubjects::find()
                .filter(dublin_metadata_ar_subjects::Column::SubjectId.is_in(subject_ids))
                .all(&self.db_session)
                .await?
                .into_iter()
                .map(|s| s.metadata_id)
                .collect();

            if metadata_ids.is_empty() {
                return Ok((Vec::new(), 0));
            }

            let location_ids: Vec<i32> = ::entity::dublin_metadata_ar::Entity::find()
                .filter(::entity::dublin_metadata_ar::Column::Id.is_in(metadata_ids))
                .filter(::entity::dublin_metadata_ar::Column::LocationArId.is_not_null())
                .all(&self.db_session)
                .await?
                .into_iter()
                .filter_map(|m| m.location_ar_id)
                .collect();

            if location_ids.is_empty() {
                return Ok((Vec::new(), 0));
            }

            query =
                query.filter(entity::dublin_metadata_location_ar::Column::Id.is_in(location_ids));
        }

        let location_pages = query.paginate(&self.db_session, per_page);
        let num_pages = location_pages.num_pages().await?;
        Ok((location_pages.fetch_page(page).await?, num_pages))
    }

    async fn list_paginated_en(
        &self,
        page: u64,
        per_page: u64,
        query_term: Option<String>,
        collection_id: Option<i32>,
    ) -> Result<(Vec<DublinMetadataLocationEnModel>, u64), DbErr> {
        let subject_ids: Vec<i32> = if let Some(coll_id) = collection_id {
            let collection_has_subjects = CollectionEnSubjects::find()
                .filter(collection_en_subjects::Column::CollectionEnId.eq(coll_id))
                .count(&self.db_session)
                .await?;

            if collection_has_subjects == 0 {
                return Ok((Vec::new(), 0));
            }

            let subject_ids: Vec<i32> = CollectionEnSubjects::find()
                .filter(collection_en_subjects::Column::CollectionEnId.eq(coll_id))
                .all(&self.db_session)
                .await?
                .into_iter()
                .map(|s| s.subject_en_id)
                .collect();
            subject_ids
        } else {
            vec![]
        };

        let mut query = DublinMetadataLocationEn::find();

        if let Some(term) = query_term {
            let query_string = format!("%{}%", term.to_lowercase());
            let query_filter = Func::lower(Expr::col(
                entity::dublin_metadata_location_en::Column::Location,
            ))
            .like(&query_string);
            query = query.filter(query_filter);
        }

        if !subject_ids.is_empty() {
            let metadata_ids: Vec<i32> = DublinMetadataEnSubjects::find()
                .filter(dublin_metadata_en_subjects::Column::SubjectId.is_in(subject_ids))
                .all(&self.db_session)
                .await?
                .into_iter()
                .map(|s| s.metadata_id)
                .collect();

            if metadata_ids.is_empty() {
                return Ok((Vec::new(), 0));
            }

            let location_ids: Vec<i32> = ::entity::dublin_metadata_en::Entity::find()
                .filter(::entity::dublin_metadata_en::Column::Id.is_in(metadata_ids))
                .filter(::entity::dublin_metadata_en::Column::LocationEnId.is_not_null())
                .all(&self.db_session)
                .await?
                .into_iter()
                .filter_map(|m| m.location_en_id)
                .collect();

            if location_ids.is_empty() {
                return Ok((Vec::new(), 0));
            }

            query =
                query.filter(entity::dublin_metadata_location_en::Column::Id.is_in(location_ids));
        }

        let location_pages = query.paginate(&self.db_session, per_page);
        let num_pages = location_pages.num_pages().await?;
        Ok((location_pages.fetch_page(page).await?, num_pages))
    }

    async fn verify_locations_exist(
        &self,
        location_ids: Vec<i32>,
        metadata_language: MetadataLanguage,
    ) -> Result<bool, DbErr> {
        let flag = match metadata_language {
            MetadataLanguage::English => {
                let rows: Vec<DublinMetadataLocationEnModel> = DublinMetadataLocationEn::find()
                    .filter(
                        ::entity::dublin_metadata_location_en::Column::Id
                            .is_in(location_ids.clone()),
                    )
                    .all(&self.db_session)
                    .await?;
                rows.len() == location_ids.len()
            }
            MetadataLanguage::Arabic => {
                let rows: Vec<DublinMetadataLocationArModel> = DublinMetadataLocationAr::find()
                    .filter(
                        ::entity::dublin_metadata_location_ar::Column::Id
                            .is_in(location_ids.clone()),
                    )
                    .all(&self.db_session)
                    .await?;
                rows.len() == location_ids.len()
            }
        };
        Ok(flag)
    }

    async fn update_one(
        &self,
        location_id: i32,
        update_location_request: UpdateLocationRequest,
    ) -> Result<Option<LocationResponse>, DbErr> {
        let result = match update_location_request.lang {
            MetadataLanguage::English => {
                let location = DublinMetadataLocationEn::find_by_id(location_id)
                    .one(&self.db_session)
                    .await?;
                if let Some(existing_location) = location {
                    let mut active_location = existing_location.into_active_model();
                    active_location.location = ActiveValue::Set(update_location_request.location);
                    let updated_location = active_location.update(&self.db_session).await?;
                    Some(LocationResponse {
                        id: updated_location.id,
                        location: updated_location.location,
                    })
                } else {
                    None
                }
            }
            MetadataLanguage::Arabic => {
                let location = DublinMetadataLocationAr::find_by_id(location_id)
                    .one(&self.db_session)
                    .await?;
                if let Some(existing_location) = location {
                    let mut active_location = existing_location.into_active_model();
                    active_location.location = ActiveValue::Set(update_location_request.location);
                    let updated_location = active_location.update(&self.db_session).await?;
                    Some(LocationResponse {
                        id: updated_location.id,
                        location: updated_location.location,
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
        location_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<()>, DbErr> {
        let deletion = match metadata_language {
            MetadataLanguage::English => {
                DublinMetadataLocationEn::delete_by_id(location_id)
                    .exec(&self.db_session)
                    .await?
            }
            MetadataLanguage::Arabic => {
                DublinMetadataLocationAr::delete_by_id(location_id)
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
        location_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<LocationResponse>, DbErr> {
        let result = match metadata_language {
            MetadataLanguage::English => {
                let location = DublinMetadataLocationEn::find_by_id(location_id)
                    .one(&self.db_session)
                    .await?;
                location.map(|s| LocationResponse {
                    id: s.id,
                    location: s.location,
                })
            }
            MetadataLanguage::Arabic => {
                let location = DublinMetadataLocationAr::find_by_id(location_id)
                    .one(&self.db_session)
                    .await?;
                location.map(|s| LocationResponse {
                    id: s.id,
                    location: s.location,
                })
            }
        };
        Ok(result)
    }
}
