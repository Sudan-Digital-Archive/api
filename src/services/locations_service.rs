//! Service layer for managing archive metadata locations.
//!
//! This module handles the business logic for creating and listing location terms
//! that are used to categorize archival records in both Arabic and English.

use crate::models::common::MetadataLanguage;
use crate::models::request::{CreateLocationRequest, UpdateLocationRequest};
use crate::models::response::{ListLocationsResponse, LocationResponse};
use crate::repos::locations_repo::LocationsRepo;
use axum::response::{IntoResponse, Response};
use axum::Json;
use http::StatusCode;
use sea_orm::DbErr;
use std::sync::Arc;
use tracing::{error, info, warn};

#[derive(Clone)]
pub struct LocationsService {
    pub locations_repo: Arc<dyn LocationsRepo>,
}

impl LocationsService {
    pub async fn create_one(self, payload: CreateLocationRequest) -> Response {
        info!(
            "Creating new {} location {}...",
            payload.lang, payload.location
        );
        let write_result = self.locations_repo.write_one(payload.clone()).await;
        match write_result {
            Err(write_error) => {
                if write_error
                    .to_string()
                    .contains("duplicate key value violates unique constraint")
                {
                    warn!(%write_error,
                        "Can't write {} location since location {} already exists",
                        payload.lang, payload.location);
                    return (
                        StatusCode::BAD_REQUEST,
                        format!("Location {} already exists", payload.location),
                    )
                        .into_response();
                }
                error!(%write_error, "Error occurred writing location");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
            Ok(new_location) => (StatusCode::CREATED, Json(new_location)).into_response(),
        }
    }

    pub async fn get_one(self, id: i32, lang: MetadataLanguage) -> Response {
        info!("Getting location with id {} and lang {:?}", id, lang);
        let result = self.locations_repo.get_one(id, lang).await;

        match result {
            Err(err) => {
                error!(%err, "Error occurred retrieving location");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
            Ok(location) => match location {
                Some(l) => Json(l).into_response(),
                None => (StatusCode::NOT_FOUND, "Location not found").into_response(),
            },
        }
    }

    pub async fn list(
        self,
        page: u64,
        per_page: u64,
        metadata_language: MetadataLanguage,
        query_term: Option<String>,
        in_collection_id: Option<i32>,
    ) -> Response {
        info!("Getting page {page} of {metadata_language} locations with per page {per_page}...");
        match metadata_language {
            MetadataLanguage::Arabic => {
                match self
                    .locations_repo
                    .list_paginated_ar(page, per_page, query_term, in_collection_id)
                    .await
                {
                    Ok(rows) => {
                        let list_locations_resp = ListLocationsResponse {
                            items: rows
                                .0
                                .into_iter()
                                .map(|l| LocationResponse {
                                    id: l.id,
                                    location: l.location,
                                })
                                .collect(),
                            num_pages: rows.1,
                            page,
                            per_page,
                        };
                        Json(list_locations_resp).into_response()
                    }
                    Err(err) => {
                        error!(%err, "Error occurred paginating {metadata_language} locations");
                        (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error")
                            .into_response()
                    }
                }
            }
            MetadataLanguage::English => {
                match self
                    .locations_repo
                    .list_paginated_en(page, per_page, query_term, in_collection_id)
                    .await
                {
                    Ok(rows) => {
                        let list_locations_resp = ListLocationsResponse {
                            items: rows
                                .0
                                .into_iter()
                                .map(|l| LocationResponse {
                                    id: l.id,
                                    location: l.location,
                                })
                                .collect(),
                            num_pages: rows.1,
                            page,
                            per_page,
                        };
                        Json(list_locations_resp).into_response()
                    }
                    Err(err) => {
                        error!(%err, "Error occurred paginating {metadata_language} locations");
                        (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error")
                            .into_response()
                    }
                }
            }
        }
    }

    pub async fn verify_locations_exist(
        self,
        location_ids: Vec<i32>,
        metadata_language: MetadataLanguage,
    ) -> Result<bool, DbErr> {
        self.locations_repo
            .verify_locations_exist(location_ids, metadata_language)
            .await
    }

    pub async fn update_one(self, location_id: i32, payload: UpdateLocationRequest) -> Response {
        info!(
            "Updating {} location with id {} to new text: {}...",
            payload.lang, location_id, payload.location
        );
        let update_result = self.locations_repo.update_one(location_id, payload).await;
        match update_result {
            Err(err) => {
                if err
                    .to_string()
                    .contains("duplicate key value violates unique constraint")
                {
                    warn!(%err, "Can't update location since new text already exists");
                    return (
                        StatusCode::BAD_REQUEST,
                        "Location with this text already exists".to_string(),
                    )
                        .into_response();
                }
                error!(%err, "Error occurred updating location");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
            Ok(Some(updated_location)) => (StatusCode::OK, Json(updated_location)).into_response(),
            Ok(None) => (StatusCode::NOT_FOUND, "Location not found").into_response(),
        }
    }

    pub async fn delete_one(
        self,
        location_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Response {
        info!("Deleting {metadata_language} location with id {location_id}...");
        let deletion_result = self
            .locations_repo
            .delete_one(location_id, metadata_language)
            .await;

        match deletion_result {
            Ok(successful_delete) => {
                if successful_delete.is_some() {
                    (StatusCode::OK, "Location deleted").into_response()
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
                        "Can't delete {metadata_language} location with id {location_id} since it's being referenced by another table"
                    );
                    return (
                        StatusCode::BAD_REQUEST,
                        format!(
                            "Location with id {location_id} is being referenced by another table"
                        ),
                    )
                        .into_response();
                }
                error!(%db_err, "Error occurred deleting {metadata_language} location");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
        }
    }
}
