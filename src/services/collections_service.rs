//! Service layer for managing collections in the digital archive.
//!
//! This module handles the business logic for creating, retrieving, updating, and deleting
//! collections, including their associated subjects in both Arabic and English.

use crate::models::common::MetadataLanguage;
use crate::models::response::{CollectionResponse, ListCollectionsResponse};
use crate::repos::collections_repo::CollectionsRepo;
use crate::repos::subjects_repo::SubjectsRepo;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use entity::collection_en::Model as CollectionEnModel;
use std::sync::Arc;
use tracing::{error, info};

/// Service for managing collections and their associated subjects.
/// Uses dynamic traits for dependency injection
#[derive(Clone)]
pub struct CollectionsService {
    pub collections_repo: Arc<dyn CollectionsRepo>,
    pub subjects_repo: Arc<dyn SubjectsRepo>,
}

impl CollectionsService {
    /// Lists paginated collections with optional filtering by language and visibility.
    ///
    /// # Arguments
    /// * `lang` - The language (English or Arabic)
    /// * `page` - Page number (0-based)
    /// * `per_page` - Items per page
    /// * `is_public` - Optional filter for public/private collections
    ///
    /// # Returns
    /// JSON response containing paginated collections or an error response
    pub async fn list(
        self,
        lang: MetadataLanguage,
        page: u64,
        per_page: u64,
        is_public: Option<bool>,
    ) -> Response {
        info!("Getting page {} of collections with lang {:?}", page, lang);

        let result = match lang {
            MetadataLanguage::English => {
                self.collections_repo
                    .list_paginated_en(page, per_page, is_public)
                    .await
            }
            MetadataLanguage::Arabic => {
                match self
                    .collections_repo
                    .list_paginated_ar(page, per_page, is_public)
                    .await
                {
                    Ok(ar_result) => {
                        // Convert Arabic models to English models for uniform response
                        let converted: Vec<CollectionEnModel> = ar_result
                            .0
                            .into_iter()
                            .map(|ar| CollectionEnModel {
                                id: ar.id,
                                title: ar.title,
                                description: ar.description,
                                is_public: ar.is_public,
                            })
                            .collect();
                        Ok((converted, ar_result.1))
                    }
                    Err(e) => Err(e),
                }
            }
        };

        match result {
            Err(err) => {
                error!(%err, "Error occurred paginating collections");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
            Ok((collections, num_pages)) => {
                let resp = ListCollectionsResponse {
                    items: collections.into_iter().map(Into::into).collect(),
                    num_pages,
                    page,
                    per_page,
                };
                Json(resp).into_response()
            }
        }
    }

    /// Retrieves a single collection by ID with its associated subjects.
    ///
    /// # Arguments
    /// * `id` - The unique identifier of the collection
    /// * `lang` - The language (English or Arabic)
    ///
    /// # Returns
    /// JSON response containing the collection details or an error response
    pub async fn get_one(self, id: i32, lang: MetadataLanguage) -> Response {
        info!("Getting collection with id {} and lang {:?}", id, lang);
        let result = self.collections_repo.get_one(id, lang).await;

        match result {
            Err(err) => {
                error!(%err, "Error occurred retrieving collection");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
            Ok(collection) => match collection {
                Some(c) => Json(CollectionResponse::from(c)).into_response(),
                None => (StatusCode::NOT_FOUND, "Collection not found").into_response(),
            },
        }
    }

    /// Creates a new collection with associated subjects.
    ///
    /// # Arguments
    /// * `title` - Collection title
    /// * `description` - Optional collection description
    /// * `is_public` - Whether the collection is publicly visible
    /// * `subject_ids` - List of subject IDs to associate
    /// * `lang` - The language (English or Arabic)
    ///
    /// # Returns
    /// Response indicating success with the created collection ID or an error
    pub async fn create_one(
        self,
        title: String,
        description: Option<String>,
        is_public: bool,
        subject_ids: Vec<i32>,
        lang: MetadataLanguage,
    ) -> Response {
        info!(
            "Creating new collection with title '{}' in {:?}",
            title, lang
        );

        // Verify subjects exist using the subjects_repo
        match self
            .subjects_repo
            .verify_subjects_exist(subject_ids.clone(), lang)
            .await
        {
            Err(err) => {
                error!(%err, "Error verifying subjects existence");
                return (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error")
                    .into_response();
            }
            Ok(false) => {
                return (StatusCode::BAD_REQUEST, "One or more subjects do not exist")
                    .into_response();
            }
            Ok(true) => {}
        }

        let result = self
            .collections_repo
            .create_one(title, description, is_public, subject_ids, lang)
            .await;

        match result {
            Err(err) => {
                error!(%err, "Error occurred creating collection");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
            Ok(id) => {
                info!("Collection created with id: {}", id);
                (
                    StatusCode::CREATED,
                    format!("Collection created with id: {}", id),
                )
                    .into_response()
            }
        }
    }

    /// Updates an existing collection with new data (idempotent PUT).
    /// Replaces all fields including subjects.
    ///
    /// # Arguments
    /// * `id` - The unique identifier of the collection
    /// * `title` - New collection title
    /// * `description` - New optional description
    /// * `is_public` - New visibility status
    /// * `subject_ids` - New list of subject IDs (replaces existing)
    /// * `lang` - The language (English or Arabic)
    ///
    /// # Returns
    /// JSON response containing the updated collection or an error response
    pub async fn update_one(
        self,
        id: i32,
        title: String,
        description: Option<String>,
        is_public: bool,
        subject_ids: Vec<i32>,
        lang: MetadataLanguage,
    ) -> Response {
        info!("Updating collection with id {} in {:?}", id, lang);

        // Verify subjects exist using the subjects_repo
        match self
            .subjects_repo
            .verify_subjects_exist(subject_ids.clone(), lang)
            .await
        {
            Err(err) => {
                error!(%err, "Error verifying subjects existence");
                return (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error")
                    .into_response();
            }
            Ok(false) => {
                return (StatusCode::BAD_REQUEST, "One or more subjects do not exist")
                    .into_response();
            }
            Ok(true) => {}
        }

        let result = self
            .collections_repo
            .update_one(id, title, description, is_public, subject_ids, lang)
            .await;

        match result {
            Err(err) => {
                error!(%err, "Error occurred updating collection");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
            Ok(collection) => match collection {
                Some(c) => Json(CollectionResponse::from(c)).into_response(),
                None => (StatusCode::NOT_FOUND, "Collection not found").into_response(),
            },
        }
    }

    /// Deletes a collection and all its relationships.
    ///
    /// # Arguments
    /// * `id` - The unique identifier of the collection
    /// * `lang` - The language (English or Arabic)
    ///
    /// # Returns
    /// Response indicating success or failure of the deletion
    pub async fn delete_one(self, id: i32, lang: MetadataLanguage) -> Response {
        info!("Deleting collection with id {} in {:?}", id, lang);

        let result = self.collections_repo.delete_one(id, lang).await;

        match result {
            Err(err) => {
                error!(%err, "Error occurred deleting collection");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
            Ok(collection) => match collection {
                Some(_) => (StatusCode::OK, "Collection deleted").into_response(),
                None => (StatusCode::NOT_FOUND, "Collection not found").into_response(),
            },
        }
    }
}

impl From<CollectionEnModel> for CollectionResponse {
    fn from(model: CollectionEnModel) -> Self {
        Self {
            id: model.id,
            title: model.title,
            description: model.description,
            is_public: model.is_public,
        }
    }
}
