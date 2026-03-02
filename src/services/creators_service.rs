//! Service layer for managing archive metadata creators.
//!
//! This module handles the business logic for creating and listing creator terms
//! that are used to categorize archival records in both Arabic and English.

use crate::models::common::MetadataLanguage;
use crate::models::request::{CreateCreatorRequest, UpdateCreatorRequest};
use crate::models::response::{CreatorResponse, ListCreatorsResponse};
use crate::repos::creators_repo::CreatorsRepo;
use axum::response::{IntoResponse, Response};
use axum::Json;
use http::StatusCode;
use sea_orm::DbErr;
use std::sync::Arc;
use tracing::{error, info, warn};

#[derive(Clone)]
pub struct CreatorsService {
    pub creators_repo: Arc<dyn CreatorsRepo>,
}

impl CreatorsService {
    pub async fn create_one(self, payload: CreateCreatorRequest) -> Response {
        info!(
            "Creating new {} creator {}...",
            payload.lang, payload.creator
        );
        let write_result = self.creators_repo.write_one(payload.clone()).await;
        match write_result {
            Err(write_error) => {
                if write_error
                    .to_string()
                    .contains("duplicate key value violates unique constraint")
                {
                    warn!(%write_error,
                        "Can't write {} creator since creator {} already exists",
                        payload.lang, payload.creator);
                    return (
                        StatusCode::BAD_REQUEST,
                        format!("Creator {} already exists", payload.creator),
                    )
                        .into_response();
                }
                error!(%write_error, "Error occurred writing creator");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
            Ok(new_creator) => (StatusCode::CREATED, Json(new_creator)).into_response(),
        }
    }

    pub async fn get_one(self, id: i32, lang: MetadataLanguage) -> Response {
        info!("Getting creator with id {} and lang {:?}", id, lang);
        let result = self.creators_repo.get_one(id, lang).await;

        match result {
            Err(err) => {
                error!(%err, "Error occurred retrieving creator");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
            Ok(creator) => match creator {
                Some(c) => Json(c).into_response(),
                None => (StatusCode::NOT_FOUND, "Creator not found").into_response(),
            },
        }
    }

    pub async fn list(
        self,
        page: u64,
        per_page: u64,
        metadata_language: MetadataLanguage,
        query_term: Option<String>,
    ) -> Response {
        info!("Getting page {page} of {metadata_language} creators with per page {per_page}...");
        match metadata_language {
            MetadataLanguage::Arabic => {
                match self
                    .creators_repo
                    .list_paginated_ar(page, per_page, query_term)
                    .await
                {
                    Ok(rows) => {
                        let list_creators_resp = ListCreatorsResponse {
                            items: rows
                                .0
                                .into_iter()
                                .map(|c| CreatorResponse {
                                    id: c.id,
                                    creator: c.creator,
                                })
                                .collect(),
                            num_pages: rows.1,
                            page,
                            per_page,
                        };
                        Json(list_creators_resp).into_response()
                    }
                    Err(err) => {
                        error!(%err, "Error occurred paginating {metadata_language} creators");
                        (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error")
                            .into_response()
                    }
                }
            }
            MetadataLanguage::English => {
                match self
                    .creators_repo
                    .list_paginated_en(page, per_page, query_term)
                    .await
                {
                    Ok(rows) => {
                        let list_creators_resp = ListCreatorsResponse {
                            items: rows
                                .0
                                .into_iter()
                                .map(|c| CreatorResponse {
                                    id: c.id,
                                    creator: c.creator,
                                })
                                .collect(),
                            num_pages: rows.1,
                            page,
                            per_page,
                        };
                        Json(list_creators_resp).into_response()
                    }
                    Err(err) => {
                        error!(%err, "Error occurred paginating {metadata_language} creators");
                        (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error")
                            .into_response()
                    }
                }
            }
        }
    }

    pub async fn verify_creators_exist(
        self,
        creator_ids: Vec<i32>,
        metadata_language: MetadataLanguage,
    ) -> Result<bool, DbErr> {
        self.creators_repo
            .verify_creators_exist(creator_ids, metadata_language)
            .await
    }

    pub async fn update_one(self, creator_id: i32, payload: UpdateCreatorRequest) -> Response {
        info!(
            "Updating {} creator with id {} to new text: {}...",
            payload.lang, creator_id, payload.creator
        );
        let update_result = self.creators_repo.update_one(creator_id, payload).await;
        match update_result {
            Err(err) => {
                if err
                    .to_string()
                    .contains("duplicate key value violates unique constraint")
                {
                    warn!(%err, "Can't update creator since new text already exists");
                    return (
                        StatusCode::BAD_REQUEST,
                        "Creator with this text already exists".to_string(),
                    )
                        .into_response();
                }
                error!(%err, "Error occurred updating creator");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
            Ok(Some(updated_creator)) => (StatusCode::OK, Json(updated_creator)).into_response(),
            Ok(None) => (StatusCode::NOT_FOUND, "Creator not found").into_response(),
        }
    }

    pub async fn delete_one(
        self,
        creator_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Response {
        info!("Deleting {metadata_language} creator with id {creator_id}...");
        let deletion_result = self
            .creators_repo
            .delete_one(creator_id, metadata_language)
            .await;

        match deletion_result {
            Ok(successful_delete) => {
                if successful_delete.is_some() {
                    (StatusCode::OK, "Creator deleted").into_response()
                } else {
                    (StatusCode::NOT_FOUND, "No such record").into_response()
                }
            }
            Err(db_err) => {
                if db_err
                    .to_string()
                    .contains("violates foreign key constraint")
                {
                    warn!(%db_err,
                        "Can't delete {metadata_language} creator with id {creator_id} since it's being referenced by another table"
                    );
                    return (
                        StatusCode::BAD_REQUEST,
                        format!(
                            "Creator with id {creator_id} is being referenced by another table"
                        ),
                    )
                        .into_response();
                }
                error!(%db_err, "Error occurred deleting {metadata_language} creator");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
        }
    }
}
