//! Repository module for managing contributor role metadata in the digital archive.
//!
//! This module provides functionality for creating and listing contributor role terms
//! that can be used to describe roles of contributors to archived content in both Arabic and English.

use crate::models::common::MetadataLanguage;
use crate::models::request::{CreateContributorRoleRequest, UpdateContributorRoleRequest};
use crate::models::response::ContributorRoleResponse;
use ::entity::collection_ar_subjects::Entity as CollectionArSubjects;
use ::entity::collection_en_subjects::Entity as CollectionEnSubjects;
use ::entity::dublin_metadata_ar_subjects::Entity as DublinMetadataArSubjects;
use ::entity::dublin_metadata_contributor_role_ar::ActiveModel as DublinMetadataContributorRoleArActiveModel;
use ::entity::dublin_metadata_contributor_role_ar::Entity as DublinMetadataContributorRoleAr;
use ::entity::dublin_metadata_contributor_role_ar::Model as DublinMetadataContributorRoleArModel;
use ::entity::dublin_metadata_contributor_role_en::ActiveModel as DublinMetadataContributorRoleEnActiveModel;
use ::entity::dublin_metadata_contributor_role_en::Entity as DublinMetadataContributorRoleEn;
use ::entity::dublin_metadata_contributor_role_en::Model as DublinMetadataContributorRoleEnModel;
use ::entity::dublin_metadata_en_subjects::Entity as DublinMetadataEnSubjects;
use async_trait::async_trait;
use entity::{
    collection_ar_subjects, collection_en_subjects, dublin_metadata_ar_subjects,
    dublin_metadata_contributor_role_ar, dublin_metadata_contributor_role_en,
    dublin_metadata_en_subjects,
};
use sea_orm::prelude::Expr;
use sea_orm::sea_query::{ExprTrait, Func, SelectStatement};
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, DatabaseConnection, DbErr, EntityTrait,
    IntoActiveModel, JoinType, PaginatorTrait, QueryFilter, QuerySelect, QueryTrait, RelationTrait,
};
use std::collections::HashSet;

/// Repository implementation for database operations on contributor roles.
#[derive(Debug, Clone, Default)]
pub struct DBContributorRolesRepo {
    pub db_session: DatabaseConnection,
}

/// Defines the interface for contributor role-related database operations.
#[async_trait]
pub trait ContributorRolesRepo: Send + Sync {
    /// Creates a new contributor role term in the specified language.
    async fn write_one(
        &self,
        create_role_request: CreateContributorRoleRequest,
    ) -> Result<ContributorRoleResponse, DbErr>;

    /// Lists Arabic contributor role terms with pagination and optional text search.
    async fn list_paginated_ar(
        &self,
        page: u64,
        per_page: u64,
        query_term: Option<String>,
        collection_id: Option<i32>,
    ) -> Result<(Vec<DublinMetadataContributorRoleArModel>, u64), DbErr>;

    /// Lists English contributor role terms with pagination and optional text search.
    async fn list_paginated_en(
        &self,
        page: u64,
        per_page: u64,
        query_term: Option<String>,
        collection_id: Option<i32>,
    ) -> Result<(Vec<DublinMetadataContributorRoleEnModel>, u64), DbErr>;

    /// Verifies that all provided contributor role IDs exist in the database.
    ///
    /// # Arguments
    /// * `role_ids` - List of contributor role IDs to verify
    /// * `metadata_language` - Language of the roles to check
    async fn verify_roles_exist(
        &self,
        role_ids: Vec<i32>,
        metadata_language: MetadataLanguage,
    ) -> Result<bool, DbErr>;

    /// Updates a contributor role term by its ID.
    ///
    /// # Arguments
    /// * `role_id` - The ID of the role to update.
    /// * `update_role_request` - The update request containing new role text and language
    async fn update_one(
        &self,
        role_id: i32,
        update_role_request: UpdateContributorRoleRequest,
    ) -> Result<Option<ContributorRoleResponse>, DbErr>;

    /// Deletes a contributor role term by its ID.
    ///
    /// # Arguments
    /// * `role_id` - The ID of the role to delete.
    /// * `metadata_language` - Language of the role to delete
    async fn delete_one(
        &self,
        role_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<()>, DbErr>;

    /// Retrieves a single contributor role term by its ID.
    ///
    /// # Arguments
    /// * `role_id` - The ID of the role to retrieve.
    /// * `metadata_language` - Language of the role to retrieve
    async fn get_one(
        &self,
        role_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<ContributorRoleResponse>, DbErr>;
}

#[async_trait]
impl ContributorRolesRepo for DBContributorRolesRepo {
    async fn write_one(
        &self,
        create_role_request: CreateContributorRoleRequest,
    ) -> Result<ContributorRoleResponse, DbErr> {
        let resp = match create_role_request.lang {
            MetadataLanguage::English => {
                let role = DublinMetadataContributorRoleEnActiveModel {
                    id: Default::default(),
                    role: ActiveValue::Set(create_role_request.role),
                };
                let new_role = role.insert(&self.db_session).await?;
                ContributorRoleResponse {
                    id: new_role.id,
                    role: new_role.role,
                }
            }
            MetadataLanguage::Arabic => {
                let role = DublinMetadataContributorRoleArActiveModel {
                    id: Default::default(),
                    role: ActiveValue::Set(create_role_request.role),
                };
                let new_role = role.insert(&self.db_session).await?;
                ContributorRoleResponse {
                    id: new_role.id,
                    role: new_role.role,
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
    ) -> Result<(Vec<DublinMetadataContributorRoleArModel>, u64), DbErr> {
        let mut query = DublinMetadataContributorRoleAr::find();

        if let Some(coll_id) = collection_id {
            let collection_has_subjects = CollectionArSubjects::find()
                .filter(collection_ar_subjects::Column::CollectionArId.eq(coll_id))
                .count(&self.db_session)
                .await?;

            if collection_has_subjects == 0 {
                return Ok((Vec::new(), 0));
            }

            let metadata_ids_subquery: SelectStatement = DublinMetadataArSubjects::find()
                .select_only()
                .column(dublin_metadata_ar_subjects::Column::MetadataId)
                .filter(
                    dublin_metadata_ar_subjects::Column::SubjectId.in_subquery(
                        CollectionArSubjects::find()
                            .select_only()
                            .column(collection_ar_subjects::Column::SubjectArId)
                            .filter(collection_ar_subjects::Column::CollectionArId.eq(coll_id))
                            .into_query(),
                    ),
                )
                .distinct()
                .into_query();

            query = query
                .join(
                    JoinType::InnerJoin,
                    entity::dublin_metadata_contributor_role_ar::Relation::DublinMetadataArContributors
                        .def(),
                )
                .filter(
                    entity::dublin_metadata_ar_contributors::Column::MetadataId
                        .in_subquery(metadata_ids_subquery),
                )
                .filter(entity::dublin_metadata_ar_contributors::Column::RoleId.is_not_null());
        }

        if let Some(term) = query_term {
            let query_string = format!("%{}%", term.to_lowercase());
            let query_filter = Func::lower(Expr::col(
                entity::dublin_metadata_contributor_role_ar::Column::Role,
            ))
            .like(&query_string);
            query = query.filter(query_filter);
        }

        let role_pages = query.paginate(&self.db_session, per_page);
        let num_pages = role_pages.num_pages().await?;
        Ok((role_pages.fetch_page(page).await?, num_pages))
    }

    async fn list_paginated_en(
        &self,
        page: u64,
        per_page: u64,
        query_term: Option<String>,
        collection_id: Option<i32>,
    ) -> Result<(Vec<DublinMetadataContributorRoleEnModel>, u64), DbErr> {
        let mut query = DublinMetadataContributorRoleEn::find();

        if let Some(coll_id) = collection_id {
            let collection_has_subjects = CollectionEnSubjects::find()
                .filter(collection_en_subjects::Column::CollectionEnId.eq(coll_id))
                .count(&self.db_session)
                .await?;

            if collection_has_subjects == 0 {
                return Ok((Vec::new(), 0));
            }

            let metadata_ids_subquery: SelectStatement = DublinMetadataEnSubjects::find()
                .select_only()
                .column(dublin_metadata_en_subjects::Column::MetadataId)
                .filter(
                    dublin_metadata_en_subjects::Column::SubjectId.in_subquery(
                        CollectionEnSubjects::find()
                            .select_only()
                            .column(collection_en_subjects::Column::SubjectEnId)
                            .filter(collection_en_subjects::Column::CollectionEnId.eq(coll_id))
                            .into_query(),
                    ),
                )
                .distinct()
                .into_query();

            query = query
                .join(
                    JoinType::InnerJoin,
                    entity::dublin_metadata_contributor_role_en::Relation::DublinMetadataEnContributors
                        .def(),
                )
                .filter(
                    entity::dublin_metadata_en_contributors::Column::MetadataId
                        .in_subquery(metadata_ids_subquery),
                )
                .filter(entity::dublin_metadata_en_contributors::Column::RoleId.is_not_null());
        }

        if let Some(term) = query_term {
            let query_string = format!("%{}%", term.to_lowercase());
            let query_filter = Func::lower(Expr::col(
                entity::dublin_metadata_contributor_role_en::Column::Role,
            ))
            .like(&query_string);
            query = query.filter(query_filter);
        }

        let role_pages = query.paginate(&self.db_session, per_page);
        let num_pages = role_pages.num_pages().await?;
        Ok((role_pages.fetch_page(page).await?, num_pages))
    }

    async fn verify_roles_exist(
        &self,
        role_ids: Vec<i32>,
        metadata_language: MetadataLanguage,
    ) -> Result<bool, DbErr> {
        let input_set: HashSet<i32> = role_ids.iter().cloned().collect();
        let flag = match metadata_language {
            MetadataLanguage::English => {
                let rows = DublinMetadataContributorRoleEn::find()
                    .filter(dublin_metadata_contributor_role_en::Column::Id.is_in(role_ids.clone()))
                    .all(&self.db_session)
                    .await?;
                let found_set: HashSet<i32> = rows.iter().map(|r| r.id).collect();
                input_set == found_set
            }
            MetadataLanguage::Arabic => {
                let rows = DublinMetadataContributorRoleAr::find()
                    .filter(dublin_metadata_contributor_role_ar::Column::Id.is_in(role_ids.clone()))
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
        role_id: i32,
        update_role_request: UpdateContributorRoleRequest,
    ) -> Result<Option<ContributorRoleResponse>, DbErr> {
        let result = match update_role_request.lang {
            MetadataLanguage::English => {
                let role = DublinMetadataContributorRoleEn::find_by_id(role_id)
                    .one(&self.db_session)
                    .await?;
                if let Some(existing_role) = role {
                    let mut active_role = existing_role.into_active_model();
                    active_role.role = ActiveValue::Set(update_role_request.role);
                    let updated_role = active_role.update(&self.db_session).await?;
                    Some(ContributorRoleResponse {
                        id: updated_role.id,
                        role: updated_role.role,
                    })
                } else {
                    None
                }
            }
            MetadataLanguage::Arabic => {
                let role = DublinMetadataContributorRoleAr::find_by_id(role_id)
                    .one(&self.db_session)
                    .await?;
                if let Some(existing_role) = role {
                    let mut active_role = existing_role.into_active_model();
                    active_role.role = ActiveValue::Set(update_role_request.role);
                    let updated_role = active_role.update(&self.db_session).await?;
                    Some(ContributorRoleResponse {
                        id: updated_role.id,
                        role: updated_role.role,
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
        role_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<()>, DbErr> {
        let deletion = match metadata_language {
            MetadataLanguage::English => {
                DublinMetadataContributorRoleEn::delete_by_id(role_id)
                    .exec(&self.db_session)
                    .await?
            }
            MetadataLanguage::Arabic => {
                DublinMetadataContributorRoleAr::delete_by_id(role_id)
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
        role_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<ContributorRoleResponse>, DbErr> {
        let result = match metadata_language {
            MetadataLanguage::English => {
                let role = DublinMetadataContributorRoleEn::find_by_id(role_id)
                    .one(&self.db_session)
                    .await?;
                role.map(|r| ContributorRoleResponse {
                    id: r.id,
                    role: r.role,
                })
            }
            MetadataLanguage::Arabic => {
                let role = DublinMetadataContributorRoleAr::find_by_id(role_id)
                    .one(&self.db_session)
                    .await?;
                role.map(|r| ContributorRoleResponse {
                    id: r.id,
                    role: r.role,
                })
            }
        };
        Ok(result)
    }
}
