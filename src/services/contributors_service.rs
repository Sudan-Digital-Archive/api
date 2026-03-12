//! Service layer for managing archive metadata contributors.
//!
//! This module handles the business logic for creating and listing contributor terms
//! that are used to describe contributors to archival records in both Arabic and English.

use crate::models::common::MetadataLanguage;
use crate::models::request::{CreateContributorRequest, UpdateContributorRequest};
use crate::models::response::{
    ContributorResponse, ContributorRoleResponse, ListContributorRolesArResponse,
    ListContributorRolesEnResponse, ListContributorsArResponse, ListContributorsEnResponse,
};
use crate::repos::contributor_roles_repo::ContributorRolesRepo;
use crate::repos::contributors_repo::ContributorsRepo;
use axum::response::{IntoResponse, Response};
use axum::Json;
use http::StatusCode;
use sea_orm::DbErr;
use std::sync::Arc;
use tracing::{error, info, warn};

#[derive(Clone)]
pub struct ContributorsService {
    pub contributors_repo: Arc<dyn ContributorsRepo>,
    pub contributor_roles_repo: Arc<dyn ContributorRolesRepo>,
}

#[allow(dead_code)]
impl ContributorsService {
    pub async fn create_one(self, payload: CreateContributorRequest) -> Response {
        info!(
            "Creating new {} contributor {}...",
            payload.lang, payload.contributor
        );
        let write_result = self.contributors_repo.write_one(payload.clone()).await;
        match write_result {
            Err(write_error) => {
                if write_error
                    .to_string()
                    .contains("duplicate key value violates unique constraint")
                {
                    warn!(%write_error,
                        "Can't write {} contributor since contributor {} already exists",
                        payload.lang, payload.contributor);
                    return (
                        StatusCode::BAD_REQUEST,
                        format!("Contributor {} already exists", payload.contributor),
                    )
                        .into_response();
                }
                error!(%write_error, "Error occurred writing contributor");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
            Ok(new_contributor) => (StatusCode::CREATED, Json(new_contributor)).into_response(),
        }
    }

    pub async fn get_one(self, id: i32, lang: MetadataLanguage) -> Response {
        info!("Getting contributor with id {} and lang {:?}", id, lang);
        let result = self.contributors_repo.get_one(id, lang).await;

        match result {
            Err(err) => {
                error!(%err, "Error occurred retrieving contributor");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
            Ok(contributor) => match contributor {
                Some(c) => Json(c).into_response(),
                None => (StatusCode::NOT_FOUND, "Contributor not found").into_response(),
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
        info!(
            "Getting page {page} of {metadata_language} contributors with per page {per_page}..."
        );
        match metadata_language {
            MetadataLanguage::Arabic => {
                match self
                    .contributors_repo
                    .list_paginated_ar(page, per_page, query_term)
                    .await
                {
                    Ok(rows) => {
                        let list_contributors_resp = ListContributorsArResponse {
                            items: rows
                                .0
                                .into_iter()
                                .map(|c| ContributorResponse {
                                    id: c.id,
                                    contributor: c.contributor,
                                })
                                .collect(),
                            num_pages: rows.1,
                            page,
                            per_page,
                        };
                        Json(list_contributors_resp).into_response()
                    }
                    Err(err) => {
                        error!( % err, "Error occurred paginating {metadata_language} contributors");
                        (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error")
                            .into_response()
                    }
                }
            }
            MetadataLanguage::English => {
                match self
                    .contributors_repo
                    .list_paginated_en(page, per_page, query_term)
                    .await
                {
                    Ok(rows) => {
                        let list_contributors_resp = ListContributorsEnResponse {
                            items: rows
                                .0
                                .into_iter()
                                .map(|c| ContributorResponse {
                                    id: c.id,
                                    contributor: c.contributor,
                                })
                                .collect(),
                            num_pages: rows.1,
                            page,
                            per_page,
                        };
                        Json(list_contributors_resp).into_response()
                    }
                    Err(err) => {
                        error!( % err, "Error occurred paginating {metadata_language} contributors");
                        (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error")
                            .into_response()
                    }
                }
            }
        }
    }

    pub async fn verify_contributors_exist(
        self,
        contributor_ids: Vec<i32>,
        metadata_language: MetadataLanguage,
    ) -> Result<bool, DbErr> {
        self.contributors_repo
            .verify_contributors_exist(contributor_ids, metadata_language)
            .await
    }

    pub async fn update_one(
        self,
        contributor_id: i32,
        payload: UpdateContributorRequest,
    ) -> Response {
        info!(
            "Updating {} contributor with id {} to new text: {}...",
            payload.lang, contributor_id, payload.contributor
        );
        let update_result = self
            .contributors_repo
            .update_one(contributor_id, payload)
            .await;
        match update_result {
            Err(err) => {
                if err
                    .to_string()
                    .contains("duplicate key value violates unique constraint")
                {
                    warn!(%err,
                        "Can't update contributor since new text already exists");
                    return (
                        StatusCode::BAD_REQUEST,
                        "Contributor with this text already exists".to_string(),
                    )
                        .into_response();
                }
                error!(%err, "Error occurred updating contributor");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
            Ok(Some(updated_contributor)) => {
                (StatusCode::OK, Json(updated_contributor)).into_response()
            }
            Ok(None) => (StatusCode::NOT_FOUND, "Contributor not found").into_response(),
        }
    }

    pub async fn delete_one(
        self,
        contributor_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Response {
        info!("Deleting {metadata_language} contributor with id {contributor_id}...");
        let deletion_result = self
            .contributors_repo
            .delete_one(contributor_id, metadata_language)
            .await;

        match deletion_result {
            Ok(successful_delete) => {
                if successful_delete.is_some() {
                    (StatusCode::OK, "Contributor deleted").into_response()
                } else {
                    (StatusCode::NOT_FOUND, "No such record").into_response()
                }
            }
            Err(db_err) => {
                if db_err
                    .to_string()
                    .contains("violates foreign key constraint")
                {
                    warn!(
                        %db_err,
                        "Can't delete {metadata_language} contributor with id {contributor_id} since it's being referenced by another table"
                    );
                    return (
                        StatusCode::BAD_REQUEST,
                        format!(
                            "Contributor with id {contributor_id} is being referenced by another table"
                        ),
                    )
                        .into_response();
                }
                error!(%db_err, "Error occurred deleting {metadata_language} contributor");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
        }
    }

    pub async fn create_role(
        self,
        payload: crate::models::request::CreateContributorRoleRequest,
    ) -> Response {
        info!(
            "Creating new {} contributor role {}...",
            payload.lang, payload.role
        );
        let write_result = self.contributor_roles_repo.write_one(payload.clone()).await;
        match write_result {
            Err(write_error) => {
                if write_error
                    .to_string()
                    .contains("duplicate key value violates unique constraint")
                {
                    warn!(%write_error,
                        "Can't write {} contributor role since role {} already exists",
                        payload.lang, payload.role);
                    return (
                        StatusCode::BAD_REQUEST,
                        format!("Contributor role {} already exists", payload.role),
                    )
                        .into_response();
                }
                error!(%write_error, "Error occurred writing contributor role");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
            Ok(new_role) => (StatusCode::CREATED, Json(new_role)).into_response(),
        }
    }

    pub async fn get_role(self, id: i32, lang: MetadataLanguage) -> Response {
        info!(
            "Getting contributor role with id {} and lang {:?}",
            id, lang
        );
        let result = self.contributor_roles_repo.get_one(id, lang).await;

        match result {
            Err(err) => {
                error!(%err, "Error occurred retrieving contributor role");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
            Ok(role) => match role {
                Some(r) => Json(r).into_response(),
                None => (StatusCode::NOT_FOUND, "Contributor role not found").into_response(),
            },
        }
    }

    pub async fn list_roles(
        self,
        page: u64,
        per_page: u64,
        metadata_language: MetadataLanguage,
        query_term: Option<String>,
    ) -> Response {
        info!("Getting page {page} of {metadata_language} contributor roles with per page {per_page}...");
        match metadata_language {
            MetadataLanguage::Arabic => {
                match self
                    .contributor_roles_repo
                    .list_paginated_ar(page, per_page, query_term)
                    .await
                {
                    Ok(rows) => {
                        let list_roles_resp = ListContributorRolesArResponse {
                            items: rows
                                .0
                                .into_iter()
                                .map(|r| ContributorRoleResponse {
                                    id: r.id,
                                    role: r.role,
                                })
                                .collect(),
                            num_pages: rows.1,
                            page,
                            per_page,
                        };
                        Json(list_roles_resp).into_response()
                    }
                    Err(err) => {
                        error!( % err, "Error occurred paginating {metadata_language} contributor roles");
                        (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error")
                            .into_response()
                    }
                }
            }
            MetadataLanguage::English => {
                match self
                    .contributor_roles_repo
                    .list_paginated_en(page, per_page, query_term)
                    .await
                {
                    Ok(rows) => {
                        let list_roles_resp = ListContributorRolesEnResponse {
                            items: rows
                                .0
                                .into_iter()
                                .map(|r| ContributorRoleResponse {
                                    id: r.id,
                                    role: r.role,
                                })
                                .collect(),
                            num_pages: rows.1,
                            page,
                            per_page,
                        };
                        Json(list_roles_resp).into_response()
                    }
                    Err(err) => {
                        error!( % err, "Error occurred paginating {metadata_language} contributor roles");
                        (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error")
                            .into_response()
                    }
                }
            }
        }
    }

    pub async fn verify_roles_exist(
        self,
        role_ids: Vec<i32>,
        metadata_language: MetadataLanguage,
    ) -> Result<bool, DbErr> {
        self.contributor_roles_repo
            .verify_roles_exist(role_ids, metadata_language)
            .await
    }

    pub async fn update_role(
        self,
        role_id: i32,
        payload: crate::models::request::UpdateContributorRoleRequest,
    ) -> Response {
        info!(
            "Updating {} contributor role with id {} to new text: {}...",
            payload.lang, role_id, payload.role
        );
        let update_result = self
            .contributor_roles_repo
            .update_one(role_id, payload)
            .await;
        match update_result {
            Err(err) => {
                if err
                    .to_string()
                    .contains("duplicate key value violates unique constraint")
                {
                    warn!(%err,
                        "Can't update contributor role since new text already exists");
                    return (
                        StatusCode::BAD_REQUEST,
                        "Contributor role with this text already exists".to_string(),
                    )
                        .into_response();
                }
                error!(%err, "Error occurred updating contributor role");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
            Ok(Some(updated_role)) => (StatusCode::OK, Json(updated_role)).into_response(),
            Ok(None) => (StatusCode::NOT_FOUND, "Contributor role not found").into_response(),
        }
    }

    pub async fn delete_role(self, role_id: i32, metadata_language: MetadataLanguage) -> Response {
        info!("Deleting {metadata_language} contributor role with id {role_id}...");
        let deletion_result = self
            .contributor_roles_repo
            .delete_one(role_id, metadata_language)
            .await;

        match deletion_result {
            Ok(successful_delete) => {
                if successful_delete.is_some() {
                    (StatusCode::OK, "Contributor role deleted").into_response()
                } else {
                    (StatusCode::NOT_FOUND, "No such record").into_response()
                }
            }
            Err(db_err) => {
                if db_err
                    .to_string()
                    .contains("violates foreign key constraint")
                {
                    warn!(
                        %db_err,
                        "Can't delete {metadata_language} contributor role with id {role_id} since it's being referenced by another table"
                    );
                    return (
                        StatusCode::BAD_REQUEST,
                        format!(
                            "Contributor role with id {role_id} is being referenced by another table"
                        ),
                    )
                        .into_response();
                }
                error!(%db_err, "Error occurred deleting {metadata_language} contributor role");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
        }
    }
}
