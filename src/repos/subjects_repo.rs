//! Repository module for managing subject metadata in the digital archive.
//!
//! This module provides functionality for creating and listing subject terms
//! that can be used to categorize archived content in both Arabic and English.

use crate::models::common::MetadataLanguage;
use crate::models::request::{CreateSubjectRequest, UpdateSubjectRequest};
use crate::models::response::SubjectResponse;
use ::entity::collection_ar_subjects::Entity as CollectionArSubjects;
use ::entity::collection_en_subjects::Entity as CollectionEnSubjects;
use ::entity::dublin_metadata_ar_subjects::Entity as DublinMetadataArSubjects;
use ::entity::dublin_metadata_en_subjects::Entity as DublinMetadataEnSubjects;
use ::entity::dublin_metadata_subject_ar::ActiveModel as DublinMetadataSubjectArActiveModel;
use ::entity::dublin_metadata_subject_ar::Entity as DublinMetadataSubjectAr;
use ::entity::dublin_metadata_subject_ar::Model as DublinMetadataSubjectArModel;
use ::entity::dublin_metadata_subject_en::ActiveModel as DublinMetadataSubjectEnActiveModel;
use ::entity::dublin_metadata_subject_en::Entity as DublinMetadataSubjectEn;
use ::entity::dublin_metadata_subject_en::Model as DublinMetadataSubjectEnModel;
use async_trait::async_trait;
use entity::{
    collection_ar_subjects, collection_en_subjects, dublin_metadata_ar_subjects,
    dublin_metadata_en_subjects, dublin_metadata_subject_ar, dublin_metadata_subject_en,
};
use sea_orm::prelude::Expr;
use sea_orm::sea_query::{ExprTrait, Func};
use sea_orm::{
    ActiveModelTrait, ActiveValue, DatabaseConnection, DbErr, EntityTrait, IntoActiveModel,
    PaginatorTrait,
};
use sea_orm::{ColumnTrait, QueryFilter};

/// Repository implementation for database operations on subjects.
#[derive(Debug, Clone, Default)]
pub struct DBSubjectsRepo {
    pub db_session: DatabaseConnection,
}

/// Defines the interface for subject-related database operations.
///
/// This trait provides methods for creating and retrieving subject terms
/// that can be used to categorize archived content in both Arabic and English.
#[async_trait]
pub trait SubjectsRepo: Send + Sync {
    /// Creates a new subject term in the specified language.
    ///
    /// # Arguments
    /// * `create_subject_request` - The request containing subject details and language
    async fn write_one(
        &self,
        create_subject_request: CreateSubjectRequest,
    ) -> Result<SubjectResponse, DbErr>;

    /// Lists Arabic subject terms with pagination and optional text search.
    ///
    /// # Arguments
    /// * `page` - The page number to retrieve
    /// * `per_page` - Number of records per page
    /// * `query_term` - Optional text search term
    /// * `collection_id` - Optional collection ID to filter subjects present on accessions in that collection
    async fn list_paginated_ar(
        &self,
        page: u64,
        per_page: u64,
        query_term: Option<String>,
        collection_id: Option<i32>,
    ) -> Result<(Vec<DublinMetadataSubjectArModel>, u64), DbErr>;

    /// Lists English subject terms with pagination and optional text search.
    ///
    /// # Arguments
    /// * `page` - The page number to retrieve
    /// * `per_page` - Number of records per page
    /// * `query_term` - Optional text search term
    /// * `collection_id` - Optional collection ID to filter subjects present on accessions in that collection
    async fn list_paginated_en(
        &self,
        page: u64,
        per_page: u64,
        query_term: Option<String>,
        collection_id: Option<i32>,
    ) -> Result<(Vec<DublinMetadataSubjectEnModel>, u64), DbErr>;

    /// Verifies that all provided subject IDs exist in the database.
    ///
    /// # Arguments
    /// * `subject_ids` - List of subject IDs to verify
    /// * `metadata_language` - Language of the subjects to check
    async fn verify_subjects_exist(
        &self,
        subject_ids: Vec<i32>,
        metadata_language: MetadataLanguage,
    ) -> Result<bool, DbErr>;

    /// Updates a subject term by its ID.
    ///
    /// # Arguments
    /// * `subject_id` - The ID of the subject to update.
    /// * `update_subject_request` - The update request containing new subject text and language
    async fn update_one(
        &self,
        subject_id: i32,
        update_subject_request: UpdateSubjectRequest,
    ) -> Result<Option<SubjectResponse>, DbErr>;

    /// Deletes a subject term by its ID.
    ///
    /// # Arguments
    /// * `subject_id` - The ID of the subject to delete.
    /// * `metadata_language` - Language of the subject to delete
    async fn delete_one(
        &self,
        subject_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<()>, DbErr>;

    /// Retrieves a single subject term by its ID.
    ///
    /// # Arguments
    /// * `subject_id` - The ID of the subject to retrieve.
    /// * `metadata_language` - Language of the subject to retrieve
    async fn get_one(
        &self,
        subject_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<SubjectResponse>, DbErr>;
}

#[async_trait]
impl SubjectsRepo for DBSubjectsRepo {
    async fn write_one(
        &self,
        create_subject_request: CreateSubjectRequest,
    ) -> Result<SubjectResponse, DbErr> {
        let resp = match create_subject_request.lang {
            MetadataLanguage::English => {
                let subject = DublinMetadataSubjectEnActiveModel {
                    id: Default::default(),
                    subject: ActiveValue::Set(create_subject_request.metadata_subject),
                };
                let new_subject = subject.insert(&self.db_session).await?;
                SubjectResponse {
                    id: new_subject.id,
                    subject: new_subject.subject,
                }
            }
            MetadataLanguage::Arabic => {
                let subject = DublinMetadataSubjectArActiveModel {
                    id: Default::default(),
                    subject: ActiveValue::Set(create_subject_request.metadata_subject),
                };
                let new_subject = subject.insert(&self.db_session).await?;
                SubjectResponse {
                    id: new_subject.id,
                    subject: new_subject.subject,
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
    ) -> Result<(Vec<DublinMetadataSubjectArModel>, u64), DbErr> {
        // Build the base query
        let mut query = DublinMetadataSubjectAr::find();

        // If collection filter is provided, join with metadata subjects to filter
        if let Some(coll_id) = collection_id {
            // Get the subject IDs that are part of this collection
            let collection_subjects: Vec<i32> = CollectionArSubjects::find()
                .filter(collection_ar_subjects::Column::CollectionArId.eq(coll_id))
                .all(&self.db_session)
                .await?
                .into_iter()
                .map(|cs| cs.subject_ar_id)
                .collect();

            if collection_subjects.is_empty() {
                // Collection has no subjects, return empty result
                return Ok((Vec::new(), 0));
            }

            // Get metadata IDs that have any of the collection's subjects
            let metadata_ids: Vec<i32> = DublinMetadataArSubjects::find()
                .filter(dublin_metadata_ar_subjects::Column::SubjectId.is_in(collection_subjects))
                .all(&self.db_session)
                .await?
                .into_iter()
                .map(|dms| dms.metadata_id)
                .collect::<std::collections::HashSet<_>>() // Remove duplicates
                .into_iter()
                .collect();

            if metadata_ids.is_empty() {
                // No accessions have the collection's subjects, return empty result
                return Ok((Vec::new(), 0));
            }

            // Get subject IDs that appear on those metadata records
            let subject_ids: Vec<i32> = DublinMetadataArSubjects::find()
                .filter(dublin_metadata_ar_subjects::Column::MetadataId.is_in(metadata_ids))
                .all(&self.db_session)
                .await?
                .into_iter()
                .map(|dms| dms.subject_id)
                .collect::<std::collections::HashSet<_>>() // Remove duplicates
                .into_iter()
                .collect();

            if subject_ids.is_empty() {
                return Ok((Vec::new(), 0));
            }

            // Filter subjects to only those IDs
            query = query.filter(dublin_metadata_subject_ar::Column::Id.is_in(subject_ids));
        }

        // Add text search filter if provided
        if let Some(term) = query_term {
            let query_string = format!("%{}%", term.to_lowercase());
            let query_filter = Func::lower(Expr::col(dublin_metadata_subject_ar::Column::Subject))
                .like(&query_string);
            query = query.filter(query_filter);
        }

        let subject_pages = query.paginate(&self.db_session, per_page);
        let num_pages = subject_pages.num_pages().await?;
        Ok((subject_pages.fetch_page(page).await?, num_pages))
    }

    async fn list_paginated_en(
        &self,
        page: u64,
        per_page: u64,
        query_term: Option<String>,
        collection_id: Option<i32>,
    ) -> Result<(Vec<DublinMetadataSubjectEnModel>, u64), DbErr> {
        // Build the base query
        let mut query = DublinMetadataSubjectEn::find();

        // If collection filter is provided, join with metadata subjects to filter
        if let Some(coll_id) = collection_id {
            // Get the subject IDs that are part of this collection
            let collection_subjects: Vec<i32> = CollectionEnSubjects::find()
                .filter(collection_en_subjects::Column::CollectionEnId.eq(coll_id))
                .all(&self.db_session)
                .await?
                .into_iter()
                .map(|cs| cs.subject_en_id)
                .collect();

            if collection_subjects.is_empty() {
                // Collection has no subjects, return empty result
                return Ok((Vec::new(), 0));
            }

            // Get metadata IDs that have any of the collection's subjects
            let metadata_ids: Vec<i32> = DublinMetadataEnSubjects::find()
                .filter(dublin_metadata_en_subjects::Column::SubjectId.is_in(collection_subjects))
                .all(&self.db_session)
                .await?
                .into_iter()
                .map(|dms| dms.metadata_id)
                .collect::<std::collections::HashSet<_>>() // Remove duplicates
                .into_iter()
                .collect();

            if metadata_ids.is_empty() {
                // No accessions have the collection's subjects, return empty result
                return Ok((Vec::new(), 0));
            }

            // Get subject IDs that appear on those metadata records
            let subject_ids: Vec<i32> = DublinMetadataEnSubjects::find()
                .filter(dublin_metadata_en_subjects::Column::MetadataId.is_in(metadata_ids))
                .all(&self.db_session)
                .await?
                .into_iter()
                .map(|dms| dms.subject_id)
                .collect::<std::collections::HashSet<_>>() // Remove duplicates
                .into_iter()
                .collect();

            if subject_ids.is_empty() {
                return Ok((Vec::new(), 0));
            }

            // Filter subjects to only those IDs
            query = query.filter(dublin_metadata_subject_en::Column::Id.is_in(subject_ids));
        }

        // Add text search filter if provided
        if let Some(term) = query_term {
            let query_string = format!("%{}%", term.to_lowercase());
            let query_filter = Func::lower(Expr::col(dublin_metadata_subject_en::Column::Subject))
                .like(&query_string);
            query = query.filter(query_filter);
        }

        let subject_pages = query.paginate(&self.db_session, per_page);
        let num_pages = subject_pages.num_pages().await?;
        Ok((subject_pages.fetch_page(page).await?, num_pages))
    }

    async fn verify_subjects_exist(
        &self,
        subject_ids: Vec<i32>,
        metadata_language: MetadataLanguage,
    ) -> Result<bool, DbErr> {
        let flag = match metadata_language {
            MetadataLanguage::English => {
                let rows = DublinMetadataSubjectEn::find()
                    .filter(dublin_metadata_subject_en::Column::Id.is_in(subject_ids.clone()))
                    .all(&self.db_session)
                    .await?;
                rows.len() == subject_ids.len()
            }
            MetadataLanguage::Arabic => {
                let rows = DublinMetadataSubjectAr::find()
                    .filter(dublin_metadata_subject_ar::Column::Id.is_in(subject_ids.clone()))
                    .all(&self.db_session)
                    .await?;
                rows.len() == subject_ids.len()
            }
        };
        Ok(flag)
    }

    async fn update_one(
        &self,
        subject_id: i32,
        update_subject_request: UpdateSubjectRequest,
    ) -> Result<Option<SubjectResponse>, DbErr> {
        let result = match update_subject_request.lang {
            MetadataLanguage::English => {
                let subject = DublinMetadataSubjectEn::find_by_id(subject_id)
                    .one(&self.db_session)
                    .await?;
                if let Some(existing_subject) = subject {
                    let mut active_subject = existing_subject.into_active_model();
                    active_subject.subject =
                        ActiveValue::Set(update_subject_request.metadata_subject);
                    let updated_subject = active_subject.update(&self.db_session).await?;
                    Some(SubjectResponse {
                        id: updated_subject.id,
                        subject: updated_subject.subject,
                    })
                } else {
                    None
                }
            }
            MetadataLanguage::Arabic => {
                let subject = DublinMetadataSubjectAr::find_by_id(subject_id)
                    .one(&self.db_session)
                    .await?;
                if let Some(existing_subject) = subject {
                    let mut active_subject = existing_subject.into_active_model();
                    active_subject.subject =
                        ActiveValue::Set(update_subject_request.metadata_subject);
                    let updated_subject = active_subject.update(&self.db_session).await?;
                    Some(SubjectResponse {
                        id: updated_subject.id,
                        subject: updated_subject.subject,
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
        subject_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<()>, DbErr> {
        let deletion = match metadata_language {
            MetadataLanguage::English => {
                DublinMetadataSubjectEn::delete_by_id(subject_id)
                    .exec(&self.db_session)
                    .await?
            }
            MetadataLanguage::Arabic => {
                DublinMetadataSubjectAr::delete_by_id(subject_id)
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
        subject_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<SubjectResponse>, DbErr> {
        let result = match metadata_language {
            MetadataLanguage::English => {
                let subject = DublinMetadataSubjectEn::find_by_id(subject_id)
                    .one(&self.db_session)
                    .await?;
                subject.map(|s| SubjectResponse {
                    id: s.id,
                    subject: s.subject,
                })
            }
            MetadataLanguage::Arabic => {
                let subject = DublinMetadataSubjectAr::find_by_id(subject_id)
                    .one(&self.db_session)
                    .await?;
                subject.map(|s| SubjectResponse {
                    id: s.id,
                    subject: s.subject,
                })
            }
        };
        Ok(result)
    }
}
