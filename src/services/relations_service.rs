//! Service layer for managing archive metadata relations.

use crate::models::common::MetadataLanguage;
use crate::models::request::CreateRelationRequest;
use crate::repos::relations_repo::RelationsRepo;
use axum::response::{IntoResponse, Response};
use axum::Json;
use http::StatusCode;
use std::sync::Arc;
use tracing::{error, info};

#[derive(Clone)]
pub struct RelationsService {
    pub relations_repo: Arc<dyn RelationsRepo>,
}

impl RelationsService {
    pub async fn create_one(
        self,
        metadata_id: i32,
        payload: CreateRelationRequest,
        metadata_language: MetadataLanguage,
    ) -> Response {
        info!(
            "Creating relation for metadata {} with type {:?} to accession {}",
            metadata_id, payload.relation_type, payload.related_accession_id
        );

        let existing_accessions = self
            .relations_repo
            .verify_related_accessions_exist(vec![payload.related_accession_id], metadata_language)
            .await;

        match existing_accessions {
            Err(err) => {
                error!(%err, "Error verifying related accession exists");
                return (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error")
                    .into_response();
            }
            Ok(false) => {
                return (
                    StatusCode::BAD_REQUEST,
                    "Related accession does not exist in the specified language",
                )
                    .into_response();
            }
            Ok(true) => {}
        }

        let result = self
            .relations_repo
            .write_one(
                metadata_id,
                payload.relation_type,
                payload.related_accession_id,
                metadata_language,
            )
            .await;

        match result {
            Err(err) => {
                error!(%err, "Error occurred writing relation");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
            Ok(new_relation) => (StatusCode::CREATED, Json(new_relation)).into_response(),
        }
    }

    pub async fn list(self, metadata_id: i32, metadata_language: MetadataLanguage) -> Response {
        info!(
            "Listing relations for metadata {} with lang {:?}",
            metadata_id, metadata_language
        );
        let result = self
            .relations_repo
            .list(metadata_id, metadata_language)
            .await;

        match result {
            Err(err) => {
                error!(%err, "Error occurred listing relations");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
            Ok(relations) => Json(relations).into_response(),
        }
    }

    pub async fn get_one(self, relation_id: i32, metadata_language: MetadataLanguage) -> Response {
        info!(
            "Getting relation {} with lang {:?}",
            relation_id, metadata_language
        );
        let result = self
            .relations_repo
            .get_one(relation_id, metadata_language)
            .await;

        match result {
            Err(err) => {
                error!(%err, "Error occurred retrieving relation");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
            Ok(relation) => match relation {
                Some(r) => Json(r).into_response(),
                None => (StatusCode::NOT_FOUND, "Relation not found").into_response(),
            },
        }
    }

    pub async fn delete_one(
        self,
        relation_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Response {
        info!(
            "Deleting relation {} with lang {:?}",
            relation_id, metadata_language
        );
        let result = self
            .relations_repo
            .delete_one(relation_id, metadata_language)
            .await;

        match result {
            Err(err) => {
                error!(%err, "Error occurred deleting relation");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
            Ok(deleted) => match deleted {
                Some(_) => (StatusCode::NO_CONTENT, "").into_response(),
                None => (StatusCode::NOT_FOUND, "Relation not found").into_response(),
            },
        }
    }
}
