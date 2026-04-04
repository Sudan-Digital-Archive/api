//! Repository module for managing accessions in the digital archive.
//!
//! This module provides functionality for creating, retrieving, and listing
//! accession records with their associated metadata in both Arabic and English.

use crate::models::common::MetadataLanguage;
use crate::models::request::{
    AccessionPaginationWithPrivate, CreateAccessionRequest, CreateAccessionRequestRaw,
    UpdateAccessionRequest,
};
use crate::repos::filter_builder::{build_filter_expression, FilterParams, MetadataIds};
use async_trait::async_trait;
use chrono::Utc;
use entity::accession::ActiveModel as AccessionActiveModel;
use entity::accession::Entity as Accession;
use entity::accession::Model as AccessionModel;

use crate::models::accessions::AccessionError;
use entity::accessions_with_metadata;
use entity::accessions_with_metadata::Entity as AccessionWithMetadata;
use entity::accessions_with_metadata::Model as AccessionWithMetadataModel;
use entity::dublin_metadata_ar::ActiveModel as DublinMetadataArActiveModel;
use entity::dublin_metadata_ar::Entity as DublinMetadataAr;
use entity::dublin_metadata_ar_contributors::ActiveModel as DublinMetadataArContributorsActiveModel;
use entity::dublin_metadata_ar_contributors::Entity as DublinMetadataArContributors;
use entity::dublin_metadata_ar_relations::Entity as DublinMetadataArRelations;
use entity::dublin_metadata_ar_subjects::ActiveModel as DublinMetadataSubjectsArActiveModel;
use entity::dublin_metadata_ar_subjects::Entity as DublinMetadataSubjectsAr;
use entity::dublin_metadata_en::ActiveModel as DublinMetadataEnActiveModel;
use entity::dublin_metadata_en::Entity as DublinMetadataEn;
use entity::dublin_metadata_en_contributors::ActiveModel as DublinMetadataEnContributorsActiveModel;
use entity::dublin_metadata_en_contributors::Entity as DublinMetadataEnContributors;
use entity::dublin_metadata_en_relations::Entity as DublinMetadataEnRelations;
use entity::dublin_metadata_en_subjects::ActiveModel as DublinMetadataSubjectsEnActiveModel;
use entity::dublin_metadata_en_subjects::Entity as DublinMetadataSubjectsEn;
use entity::dublin_metadata_relation_ar::Column as DublinMetadataRelationArColumn;
use entity::dublin_metadata_relation_ar::Entity as DublinMetadataRelationAr;
use entity::dublin_metadata_relation_en::Column as DublinMetadataRelationEnColumn;
use entity::dublin_metadata_relation_en::Entity as DublinMetadataRelationEn;
use entity::sea_orm_active_enums::{CrawlStatus, DublinMetadataFormat};
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, DatabaseConnection, DbErr, EntityTrait,
    PaginatorTrait, QueryFilter, TransactionTrait, TryIntoModel,
};

use uuid::Uuid;

/// Repository implementation for database operations on accessions.
#[derive(Debug, Clone, Default)]
pub struct DBAccessionsRepo {
    pub db_session: DatabaseConnection,
}

/// Defines the interface for accession-related database operations.
///
/// This trait provides methods for creating and retrieving accession records
/// along with their associated metadata in both Arabic and English.
#[async_trait]
pub trait AccessionsRepo: Send + Sync {
    /// Creates a new accession record with associated metadata.
    ///
    /// # Arguments
    /// * `create_accession_request` - The request containing accession and metadata details
    /// * `org_id` - The Browsertrix organization ID associated with the accession
    /// * `crawl_id` - The ID of the crawl operation
    /// * `job_run_id` - The ID of the job run
    /// * `crawl_status` - The status of the crawl operation
    async fn write_one(
        &self,
        create_accession_request: CreateAccessionRequest,
        org_id: Uuid,
        crawl_id: Uuid,
        job_run_id: String,
        crawl_status: CrawlStatus,
    ) -> Result<i32, DbErr>;

    /// Creates a new accession record from a raw file upload (without a web crawl).
    ///
    /// # Arguments
    /// * `create_accession_request` - The request containing accession and metadata details for raw upload
    async fn write_one_raw(
        &self,
        create_accession_request: CreateAccessionRequestRaw,
    ) -> Result<i32, DbErr>;

    /// Retrieves an accession record by its ID along with associated metadata.
    async fn get_one(
        &self,
        id: i32,
        private: bool,
    ) -> Result<Option<AccessionWithMetadataModel>, DbErr>;

    /// Lists accessions with pagination and filtering options.
    ///
    /// # Arguments
    /// * `params` - Parameters for filtering and pagination
    async fn list_paginated(
        &self,
        params: AccessionPaginationWithPrivate,
    ) -> Result<(Vec<AccessionWithMetadataModel>, u64), DbErr>;

    /// Deletes an accession record by its ID.
    ///
    /// # Arguments
    /// * `id` - The ID of the accession to delete
    async fn delete_one(&self, id: i32) -> Result<Option<AccessionModel>, AccessionError>;

    /// Updates an existing accession record with new metadata.
    ///
    /// # Arguments
    /// * `id` - The ID of the accession to update
    /// * `update_accession_request` - The request containing updated metadata details
    async fn update_one(
        &self,
        id: i32,
        update_accession_request: UpdateAccessionRequest,
    ) -> Result<Option<i32>, DbErr>;

    async fn get_dublin_metadata_id(
        &self,
        accession_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<i32>, DbErr>;

    async fn has_incoming_relations(&self, accession_id: i32) -> Result<bool, AccessionError>;
}

/// A private struct that mirrors the fields required to create an accession
/// in the database.
///
/// This acts as a unified data structure that can be created from either a
/// `CreateAccessionRequest` (for web crawls) or a `CreateAccessionRequestRaw`
/// (for raw file uploads), decoupling the public-facing request models from
/// the internal database repository logic.
struct CreateAccessionData {
    metadata_language: MetadataLanguage,
    metadata_title: String,
    metadata_description: Option<String>,
    metadata_subjects: Vec<i32>,
    metadata_time: chrono::NaiveDateTime,
    crawl_status: CrawlStatus,
    org_id: Option<Uuid>,
    crawl_id: Option<Uuid>,
    job_run_id: Option<String>,
    seed_url: String,
    is_private: bool,
    metadata_format: DublinMetadataFormat,
    s3_filename: Option<String>,
    metadata_location_en_id: Option<i32>,
    metadata_location_ar_id: Option<i32>,
    metadata_creator_en_id: Option<i32>,
    metadata_creator_ar_id: Option<i32>,
    metadata_contributor_en_ids: Vec<i32>,
    metadata_contributor_role_en_ids: Vec<Option<i32>>,
    metadata_contributor_ar_ids: Vec<i32>,
    metadata_contributor_role_ar_ids: Vec<Option<i32>>,
}

impl DBAccessionsRepo {
    /// A private helper method to create a single accession record in the database.
    ///
    /// This method contains the shared logic for creating metadata and accession
    /// entries within a single database transaction. It is called by the public-facing
    /// `write_one` and `write_one_raw` methods.
    async fn _create_one(&self, accession_data: CreateAccessionData) -> Result<i32, DbErr> {
        let txn = self.db_session.begin().await?;

        let (dublin_metadata_en_id, dublin_metadata_ar_id) = match accession_data.metadata_language
        {
            MetadataLanguage::English => {
                let metadata = DublinMetadataEnActiveModel {
                    id: Default::default(),
                    title: ActiveValue::Set(accession_data.metadata_title),
                    description: ActiveValue::Set(accession_data.metadata_description),
                    location_en_id: ActiveValue::Set(accession_data.metadata_location_en_id),
                    creator_en_id: ActiveValue::Set(accession_data.metadata_creator_en_id),
                };
                let inserted_metadata = metadata.save(&txn).await?;
                let metadata_id = inserted_metadata.try_into_model()?.id;
                let mut subject_links: Vec<DublinMetadataSubjectsEnActiveModel> = vec![];
                for subject_id in accession_data.metadata_subjects.iter() {
                    let subjects_link = DublinMetadataSubjectsEnActiveModel {
                        metadata_id: ActiveValue::Set(metadata_id),
                        subject_id: ActiveValue::Set(*subject_id),
                    };
                    subject_links.push(subjects_link);
                }
                DublinMetadataSubjectsEn::insert_many(subject_links)
                    .exec(&txn)
                    .await?;
                if !accession_data.metadata_contributor_en_ids.is_empty() {
                    let mut contributor_links: Vec<DublinMetadataEnContributorsActiveModel> =
                        vec![];
                    for (i, contributor_id) in accession_data
                        .metadata_contributor_en_ids
                        .iter()
                        .enumerate()
                    {
                        let role_id = accession_data
                            .metadata_contributor_role_en_ids
                            .get(i)
                            .copied()
                            .flatten();
                        let contributor_link = DublinMetadataEnContributorsActiveModel {
                            metadata_id: ActiveValue::Set(metadata_id),
                            contributor_id: ActiveValue::Set(*contributor_id),
                            role_id: ActiveValue::Set(role_id),
                        };
                        contributor_links.push(contributor_link);
                    }
                    DublinMetadataEnContributors::insert_many(contributor_links)
                        .exec(&txn)
                        .await?;
                }
                (Some(metadata_id), None)
            }
            MetadataLanguage::Arabic => {
                let metadata = DublinMetadataArActiveModel {
                    id: Default::default(),
                    title: ActiveValue::Set(accession_data.metadata_title),
                    description: ActiveValue::Set(accession_data.metadata_description),
                    location_ar_id: ActiveValue::Set(accession_data.metadata_location_ar_id),
                    creator_ar_id: ActiveValue::Set(accession_data.metadata_creator_ar_id),
                };
                let inserted_metadata = metadata.save(&txn).await?;
                let metadata_id = inserted_metadata.try_into_model()?.id;
                let mut subject_links: Vec<DublinMetadataSubjectsArActiveModel> = vec![];
                for subject_id in accession_data.metadata_subjects.iter() {
                    let subjects_link = DublinMetadataSubjectsArActiveModel {
                        metadata_id: ActiveValue::Set(metadata_id),
                        subject_id: ActiveValue::Set(*subject_id),
                    };
                    subject_links.push(subjects_link);
                }
                DublinMetadataSubjectsAr::insert_many(subject_links)
                    .exec(&txn)
                    .await?;
                if !accession_data.metadata_contributor_ar_ids.is_empty() {
                    let mut contributor_links: Vec<DublinMetadataArContributorsActiveModel> =
                        vec![];
                    for (i, contributor_id) in accession_data
                        .metadata_contributor_ar_ids
                        .iter()
                        .enumerate()
                    {
                        let role_id = accession_data
                            .metadata_contributor_role_ar_ids
                            .get(i)
                            .copied()
                            .flatten();
                        let contributor_link = DublinMetadataArContributorsActiveModel {
                            metadata_id: ActiveValue::Set(metadata_id),
                            contributor_id: ActiveValue::Set(*contributor_id),
                            role_id: ActiveValue::Set(role_id),
                        };
                        contributor_links.push(contributor_link);
                    }
                    DublinMetadataArContributors::insert_many(contributor_links)
                        .exec(&txn)
                        .await?;
                }
                (None, Some(metadata_id))
            }
        };

        let utc_now = Utc::now();
        let i_hate_timezones = utc_now.naive_utc();
        let accession = AccessionActiveModel {
            id: Default::default(),
            dublin_metadata_en: ActiveValue::Set(dublin_metadata_en_id),
            dublin_metadata_ar: ActiveValue::Set(dublin_metadata_ar_id),
            dublin_metadata_date: ActiveValue::Set(accession_data.metadata_time),
            crawl_status: ActiveValue::Set(accession_data.crawl_status),
            crawl_timestamp: ActiveValue::Set(i_hate_timezones),
            org_id: ActiveValue::Set(accession_data.org_id),
            crawl_id: ActiveValue::Set(accession_data.crawl_id),
            job_run_id: ActiveValue::Set(accession_data.job_run_id),
            seed_url: ActiveValue::Set(accession_data.seed_url),
            is_private: ActiveValue::Set(accession_data.is_private),
            dublin_metadata_format: ActiveValue::Set(accession_data.metadata_format),
            s3_filename: ActiveValue::Set(accession_data.s3_filename),
        };
        let saved_accession = accession.clone().save(&txn).await?;
        txn.commit().await?;
        Ok(*saved_accession.id.as_ref())
    }
}

#[async_trait]
impl AccessionsRepo for DBAccessionsRepo {
    async fn write_one(
        &self,
        create_accession_request: CreateAccessionRequest,
        org_id: Uuid,
        crawl_id: Uuid,
        job_run_id: String,
        crawl_status: CrawlStatus,
    ) -> Result<i32, DbErr> {
        let accession_data = CreateAccessionData {
            metadata_language: create_accession_request.metadata_language,
            metadata_title: create_accession_request.metadata_title,
            metadata_description: create_accession_request.metadata_description,
            metadata_subjects: create_accession_request.metadata_subjects,
            metadata_time: create_accession_request.metadata_time,
            crawl_status,
            org_id: Some(org_id),
            crawl_id: Some(crawl_id),
            job_run_id: Some(job_run_id),
            seed_url: create_accession_request.url,
            is_private: create_accession_request.is_private,
            metadata_format: create_accession_request.metadata_format,
            s3_filename: create_accession_request.s3_filename,
            metadata_location_en_id: create_accession_request.metadata_location_en_id,
            metadata_location_ar_id: create_accession_request.metadata_location_ar_id,
            metadata_creator_en_id: create_accession_request.metadata_creator_en_id,
            metadata_creator_ar_id: create_accession_request.metadata_creator_ar_id,
            metadata_contributor_en_ids: create_accession_request.metadata_contributor_en_ids,
            metadata_contributor_role_en_ids: create_accession_request
                .metadata_contributor_role_en_ids,
            metadata_contributor_ar_ids: create_accession_request.metadata_contributor_ar_ids,
            metadata_contributor_role_ar_ids: create_accession_request
                .metadata_contributor_role_ar_ids,
        };
        self._create_one(accession_data).await
    }

    async fn write_one_raw(
        &self,
        create_accession_request: CreateAccessionRequestRaw,
    ) -> Result<i32, DbErr> {
        let accession_data = CreateAccessionData {
            metadata_language: create_accession_request.metadata_language,
            metadata_title: create_accession_request.metadata_title,
            metadata_description: create_accession_request.metadata_description,
            metadata_subjects: create_accession_request.metadata_subjects,
            metadata_time: create_accession_request.metadata_time,
            crawl_status: CrawlStatus::Complete,
            org_id: None,
            crawl_id: None,
            job_run_id: None,
            seed_url: create_accession_request.original_url,
            is_private: create_accession_request.is_private,
            metadata_format: create_accession_request.metadata_format,
            s3_filename: Some(create_accession_request.s3_filename),
            metadata_location_en_id: create_accession_request.metadata_location_en_id,
            metadata_location_ar_id: create_accession_request.metadata_location_ar_id,
            metadata_creator_en_id: create_accession_request.metadata_creator_en_id,
            metadata_creator_ar_id: create_accession_request.metadata_creator_ar_id,
            metadata_contributor_en_ids: create_accession_request.metadata_contributor_en_ids,
            metadata_contributor_role_en_ids: create_accession_request
                .metadata_contributor_role_en_ids,
            metadata_contributor_ar_ids: create_accession_request.metadata_contributor_ar_ids,
            metadata_contributor_role_ar_ids: create_accession_request
                .metadata_contributor_role_ar_ids,
        };
        self._create_one(accession_data).await
    }

    async fn get_one(
        &self,
        id: i32,
        private: bool,
    ) -> Result<Option<AccessionWithMetadataModel>, DbErr> {
        let accession = AccessionWithMetadata::find()
            .filter(accessions_with_metadata::Column::Id.eq(id))
            .filter(accessions_with_metadata::Column::IsPrivate.eq(private))
            .one(&self.db_session)
            .await?;
        Ok(accession)
    }

    async fn list_paginated(
        &self,
        params: AccessionPaginationWithPrivate,
    ) -> Result<(Vec<AccessionWithMetadataModel>, u64), DbErr> {
        let metadata_subjects = if params.metadata_subjects.is_empty() {
            None
        } else {
            Some(MetadataIds {
                ids: params.metadata_subjects,
                inclusive_filter: params.metadata_subjects_inclusive_filter.unwrap_or(true),
            })
        };
        let filter_params = FilterParams {
            metadata_language: params.lang,
            metadata_subjects,
            metadata_locations: if params.metadata_locations.is_empty() {
                None
            } else {
                Some(params.metadata_locations)
            },
            metadata_creators: if params.metadata_creators.is_empty() {
                None
            } else {
                Some(params.metadata_creators)
            },
            metadata_contributors: if params.metadata_contributors.is_empty() {
                None
            } else {
                Some(MetadataIds {
                    ids: params.metadata_contributors,
                    inclusive_filter: params
                        .metadata_contributors_inclusive_filter
                        .unwrap_or(true),
                })
            },
            metadata_contributor_roles: if params.metadata_contributor_roles.is_empty() {
                None
            } else {
                Some(MetadataIds {
                    ids: params.metadata_contributor_roles,
                    inclusive_filter: params
                        .metadata_contributor_roles_inclusive_filter
                        .unwrap_or(true),
                })
            },
            query_term: params.query_term,
            url_filter: params.url_filter,
            date_from: params.date_from,
            date_to: params.date_to,
            is_private: params.is_private,
            location: params.location,
        };
        let filter_expression = build_filter_expression(filter_params);
        let accession_pages;
        if let Some(query_filter) = filter_expression {
            accession_pages = AccessionWithMetadata::find()
                .filter(query_filter)
                .paginate(&self.db_session, params.per_page);
        } else {
            accession_pages =
                AccessionWithMetadata::find().paginate(&self.db_session, params.per_page);
        }
        let num_pages = accession_pages.num_pages().await?;
        Ok((accession_pages.fetch_page(params.page).await?, num_pages))
    }

    async fn delete_one(&self, id: i32) -> Result<Option<AccessionModel>, AccessionError> {
        if self.has_incoming_relations(id).await? {
            return Err(AccessionError::ForeignKeyViolation(
                "Cannot delete accession: other accessions depend on this record".to_string(),
            ));
        }

        let txn = match self.db_session.begin().await {
            Ok(txn) => txn,
            Err(err) => return Err(AccessionError::ForeignKeyViolation(err.to_string())),
        };
        let accession = match Accession::find_by_id(id).one(&txn).await {
            Ok(acc) => acc,
            Err(err) => return Err(AccessionError::ForeignKeyViolation(err.to_string())),
        };
        match accession {
            Some(accession_record) => {
                Accession::delete_by_id(id)
                    .exec(&txn)
                    .await
                    .map_err(|e| AccessionError::ForeignKeyViolation(e.to_string()))?;
                if let Some(metadata_id) = accession_record.dublin_metadata_en {
                    let metadata_en =
                        match DublinMetadataEn::find_by_id(metadata_id).one(&txn).await {
                            Ok(m) => m,
                            Err(err) => {
                                return Err(AccessionError::ForeignKeyViolation(err.to_string()))
                            }
                        };
                    if let Some(metadata_record) = metadata_en {
                        DublinMetadataSubjectsEn::delete_many()
                            .filter(<entity::dublin_metadata_en_subjects::Entity as EntityTrait>::Column::MetadataId.eq(metadata_record.id))
                            .exec(&txn)
                            .await
                            .map_err(|e| AccessionError::ForeignKeyViolation(e.to_string()))?;
                        DublinMetadataEnContributors::delete_many()
                            .filter(<entity::dublin_metadata_en_contributors::Entity as EntityTrait>::Column::MetadataId.eq(metadata_record.id))
                            .exec(&txn)
                            .await
                            .map_err(|e| AccessionError::ForeignKeyViolation(e.to_string()))?;
                        DublinMetadataEnRelations::delete_many()
                            .filter(<entity::dublin_metadata_en_relations::Entity as EntityTrait>::Column::MetadataId.eq(metadata_record.id))
                            .exec(&txn)
                            .await
                            .map_err(|e| AccessionError::ForeignKeyViolation(e.to_string()))?;
                        DublinMetadataEn::delete_by_id(metadata_id)
                            .exec(&txn)
                            .await
                            .map_err(|e| AccessionError::ForeignKeyViolation(e.to_string()))?;
                    }
                }
                if let Some(metadata_id) = accession_record.dublin_metadata_ar {
                    let metadata_ar =
                        match DublinMetadataAr::find_by_id(metadata_id).one(&txn).await {
                            Ok(m) => m,
                            Err(err) => {
                                return Err(AccessionError::ForeignKeyViolation(err.to_string()))
                            }
                        };
                    if let Some(metadata_record) = metadata_ar {
                        DublinMetadataSubjectsAr::delete_many()
                            .filter(<entity::dublin_metadata_ar_subjects::Entity as EntityTrait>::Column::MetadataId.eq(metadata_record.id))
                            .exec(&txn)
                            .await
                            .map_err(|e| AccessionError::ForeignKeyViolation(e.to_string()))?;
                        DublinMetadataArContributors::delete_many()
                            .filter(<entity::dublin_metadata_ar_contributors::Entity as EntityTrait>::Column::MetadataId.eq(metadata_record.id))
                            .exec(&txn)
                            .await
                            .map_err(|e| AccessionError::ForeignKeyViolation(e.to_string()))?;
                        DublinMetadataArRelations::delete_many()
                            .filter(<entity::dublin_metadata_ar_relations::Entity as EntityTrait>::Column::MetadataId.eq(metadata_record.id))
                            .exec(&txn)
                            .await
                            .map_err(|e| AccessionError::ForeignKeyViolation(e.to_string()))?;
                        DublinMetadataAr::delete_by_id(metadata_id)
                            .exec(&txn)
                            .await
                            .map_err(|e| AccessionError::ForeignKeyViolation(e.to_string()))?;
                    }
                }
                txn.commit()
                    .await
                    .map_err(|e| AccessionError::ForeignKeyViolation(e.to_string()))?;
                Ok(Some(accession_record))
            }
            None => Ok(None),
        }
    }

    async fn update_one(
        &self,
        id: i32,
        update_accession_request: UpdateAccessionRequest,
    ) -> Result<Option<i32>, DbErr> {
        let txn = self.db_session.begin().await?;
        let accession = Accession::find_by_id(id).one(&self.db_session).await?;
        match accession {
            Some(accession) => {
                let mut accession_active: AccessionActiveModel = accession.clone().into();

                let location_en_id = update_accession_request.metadata_location_en_id;

                let location_ar_id = update_accession_request.metadata_location_ar_id;

                match update_accession_request.metadata_language {
                    MetadataLanguage::English => {
                        let creator_en_id = update_accession_request.metadata_creator_en_id;
                        let metadata = DublinMetadataEnActiveModel {
                            id: match accession.dublin_metadata_en {
                                Some(id) => ActiveValue::Set(id),
                                None => Default::default(),
                            },
                            title: ActiveValue::Set(update_accession_request.metadata_title),
                            description: ActiveValue::Set(
                                update_accession_request.metadata_description,
                            ),
                            location_en_id: ActiveValue::Set(location_en_id),
                            creator_en_id: ActiveValue::Set(creator_en_id),
                        };
                        let inserted_metadata = metadata.save(&txn).await?;
                        let metadata_id = inserted_metadata.try_into_model()?.id;
                        let mut new_subject_links: Vec<DublinMetadataSubjectsEnActiveModel> =
                            vec![];
                        for subject_id in update_accession_request.metadata_subjects.iter() {
                            let subjects_link = DublinMetadataSubjectsEnActiveModel {
                                metadata_id: ActiveValue::Set(metadata_id),
                                subject_id: ActiveValue::Set(*subject_id),
                            };
                            new_subject_links.push(subjects_link);
                        }
                        DublinMetadataSubjectsEn::delete_many().filter(<entity::dublin_metadata_en_subjects::Entity as EntityTrait>::Column::MetadataId.eq(metadata_id))
                            .exec(&txn)
                            .await?;
                        DublinMetadataSubjectsEn::insert_many(new_subject_links)
                            .exec(&txn)
                            .await?;
                        DublinMetadataEnContributors::delete_many()
                            .filter(<entity::dublin_metadata_en_contributors::Entity as EntityTrait>::Column::MetadataId.eq(metadata_id))
                            .exec(&txn)
                            .await?;
                        if !update_accession_request
                            .metadata_contributor_en_ids
                            .is_empty()
                        {
                            let mut new_contributor_links: Vec<
                                DublinMetadataEnContributorsActiveModel,
                            > = vec![];
                            for (i, contributor_id) in update_accession_request
                                .metadata_contributor_en_ids
                                .iter()
                                .enumerate()
                            {
                                let role_id = update_accession_request
                                    .metadata_contributor_role_en_ids
                                    .get(i)
                                    .copied()
                                    .flatten();
                                let contributor_link = DublinMetadataEnContributorsActiveModel {
                                    metadata_id: ActiveValue::Set(metadata_id),
                                    contributor_id: ActiveValue::Set(*contributor_id),
                                    role_id: ActiveValue::Set(role_id),
                                };
                                new_contributor_links.push(contributor_link);
                            }
                            DublinMetadataEnContributors::insert_many(new_contributor_links)
                                .exec(&txn)
                                .await?;
                        }
                        accession_active.dublin_metadata_en = ActiveValue::Set(Some(metadata_id));
                    }
                    MetadataLanguage::Arabic => {
                        let creator_ar_id = update_accession_request.metadata_creator_ar_id;
                        let metadata = DublinMetadataArActiveModel {
                            id: match accession.dublin_metadata_ar {
                                Some(id) => ActiveValue::Set(id),
                                None => Default::default(),
                            },
                            title: ActiveValue::Set(update_accession_request.metadata_title),
                            description: ActiveValue::Set(
                                update_accession_request.metadata_description,
                            ),
                            location_ar_id: ActiveValue::Set(location_ar_id),
                            creator_ar_id: ActiveValue::Set(creator_ar_id),
                        };
                        let inserted_metadata = metadata.save(&txn).await?;
                        let metadata_id = inserted_metadata.try_into_model()?.id;
                        let mut new_subject_links: Vec<DublinMetadataSubjectsArActiveModel> =
                            vec![];
                        for subject_id in update_accession_request.metadata_subjects.iter() {
                            let subjects_link = DublinMetadataSubjectsArActiveModel {
                                metadata_id: ActiveValue::Set(metadata_id),
                                subject_id: ActiveValue::Set(*subject_id),
                            };
                            new_subject_links.push(subjects_link);
                        }
                        DublinMetadataSubjectsAr::delete_many().filter(<entity::dublin_metadata_ar_subjects::Entity as EntityTrait>::Column::MetadataId.eq(metadata_id))
                            .exec(&txn)
                            .await?;
                        DublinMetadataSubjectsAr::insert_many(new_subject_links)
                            .exec(&txn)
                            .await?;
                        DublinMetadataArContributors::delete_many()
                            .filter(<entity::dublin_metadata_ar_contributors::Entity as EntityTrait>::Column::MetadataId.eq(metadata_id))
                            .exec(&txn)
                            .await?;
                        if !update_accession_request
                            .metadata_contributor_ar_ids
                            .is_empty()
                        {
                            let mut new_contributor_links: Vec<
                                DublinMetadataArContributorsActiveModel,
                            > = vec![];
                            for (i, contributor_id) in update_accession_request
                                .metadata_contributor_ar_ids
                                .iter()
                                .enumerate()
                            {
                                let role_id = update_accession_request
                                    .metadata_contributor_role_ar_ids
                                    .get(i)
                                    .copied()
                                    .flatten();
                                let contributor_link = DublinMetadataArContributorsActiveModel {
                                    metadata_id: ActiveValue::Set(metadata_id),
                                    contributor_id: ActiveValue::Set(*contributor_id),
                                    role_id: ActiveValue::Set(role_id),
                                };
                                new_contributor_links.push(contributor_link);
                            }
                            DublinMetadataArContributors::insert_many(new_contributor_links)
                                .exec(&txn)
                                .await?;
                        }
                        accession_active.dublin_metadata_ar = ActiveValue::Set(Some(metadata_id));
                    }
                };
                accession_active.dublin_metadata_date =
                    ActiveValue::Set(update_accession_request.metadata_time);
                accession_active.is_private = ActiveValue::Set(update_accession_request.is_private);
                accession_active.update(&txn).await?;
                txn.commit().await?;
                Ok(Some(id))
            }
            None => Ok(None),
        }
    }

    async fn get_dublin_metadata_id(
        &self,
        accession_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<i32>, DbErr> {
        let accession = Accession::find_by_id(accession_id)
            .one(&self.db_session)
            .await?;
        Ok(match metadata_language {
            MetadataLanguage::English => accession.and_then(|a| a.dublin_metadata_en),
            MetadataLanguage::Arabic => accession.and_then(|a| a.dublin_metadata_ar),
        })
    }

    async fn has_incoming_relations(&self, accession_id: i32) -> Result<bool, AccessionError> {
        let has_en = DublinMetadataRelationEn::find()
            .filter(DublinMetadataRelationEnColumn::RelatedAccessionId.eq(accession_id))
            .one(&self.db_session)
            .await
            .map_err(|e| AccessionError::ForeignKeyViolation(e.to_string()))?;

        if has_en.is_some() {
            return Ok(true);
        }

        let has_ar = DublinMetadataRelationAr::find()
            .filter(DublinMetadataRelationArColumn::RelatedAccessionId.eq(accession_id))
            .one(&self.db_session)
            .await
            .map_err(|e| AccessionError::ForeignKeyViolation(e.to_string()))?;

        Ok(has_ar.is_some())
    }
}
