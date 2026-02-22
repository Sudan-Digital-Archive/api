//! Repository module for managing collections in the digital archive.
//!
//! This module provides functionality for creating, retrieving, updating, and deleting
//! collection records with their associated subjects in both Arabic and English.
//!
//! Note: The JOIN operations to fetch subject IDs for collections are safe because
//! the API validates that collections can have at most 200 subjects (see
//! CreateCollectionRequest and UpdateCollectionRequest in src/models/request.rs).
//! This prevents the JOIN from returning an absurd amount of data.

use crate::models::common::MetadataLanguage;
use async_trait::async_trait;
use entity::collection_ar::ActiveModel as CollectionArActiveModel;
use entity::collection_ar::Entity as CollectionAr;
use entity::collection_ar_subjects::ActiveModel as CollectionArSubjectsActiveModel;
use entity::collection_ar_subjects::Entity as CollectionArSubjects;
use entity::collection_en::ActiveModel as CollectionEnActiveModel;
use entity::collection_en::Entity as CollectionEn;
use entity::collection_en::Model as CollectionEnModel;
use entity::collection_en_subjects::ActiveModel as CollectionEnSubjectsActiveModel;
use entity::collection_en_subjects::Entity as CollectionEnSubjects;
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, DatabaseConnection, DbErr, EntityTrait,
    PaginatorTrait, QueryFilter, TransactionTrait, TryIntoModel,
};

/// A collection with its associated subject IDs.
/// This is returned from repository methods to provide complete collection data.
#[derive(Debug, Clone)]
pub struct CollectionWithSubjects {
    pub collection: CollectionEnModel,
    pub subject_ids: Vec<i32>,
}

/// Repository implementation for database operations on collections.
#[derive(Debug, Clone, Default)]
pub struct DBCollectionsRepo {
    pub db_session: DatabaseConnection,
}

/// Defines the interface for collection-related database operations.
#[async_trait]
pub trait CollectionsRepo: Send + Sync {
    /// Lists English collections with pagination and optional filtering by visibility.
    /// Returns collections with their associated subject IDs.
    async fn list_paginated_en(
        &self,
        page: u64,
        per_page: u64,
        is_private: Option<bool>,
    ) -> Result<(Vec<CollectionWithSubjects>, u64), DbErr>;

    /// Lists Arabic collections with pagination and optional filtering by visibility.
    /// Returns collections converted to English models with their associated subject IDs.
    async fn list_paginated_ar(
        &self,
        page: u64,
        per_page: u64,
        is_private: Option<bool>,
    ) -> Result<(Vec<CollectionWithSubjects>, u64), DbErr>;

    /// Retrieves a single collection by ID with its associated subjects.
    async fn get_one(
        &self,
        id: i32,
        lang: MetadataLanguage,
    ) -> Result<Option<CollectionWithSubjects>, DbErr>;

    /// Creates a new collection with associated subjects in a transaction.
    async fn create_one(
        &self,
        title: String,
        description: Option<String>,
        is_private: bool,
        subject_ids: Vec<i32>,
        lang: MetadataLanguage,
    ) -> Result<i32, DbErr>;

    /// Updates an existing collection with new data and subjects in a transaction (idempotent PUT).
    /// Returns the updated collection with its associated subject IDs.
    async fn update_one(
        &self,
        id: i32,
        title: String,
        description: Option<String>,
        is_private: bool,
        subject_ids: Vec<i32>,
        lang: MetadataLanguage,
    ) -> Result<Option<CollectionWithSubjects>, DbErr>;

    /// Deletes a collection.
    ///
    /// Note: The deletion cascades to related records (subject relationships and
    /// accession relationships) due to foreign key constraints defined in the schema.
    /// No explicit deletion of these relationships is needed in this method.
    async fn delete_one(
        &self,
        id: i32,
        lang: MetadataLanguage,
    ) -> Result<Option<CollectionWithSubjects>, DbErr>;
}

#[async_trait]
impl CollectionsRepo for DBCollectionsRepo {
    async fn list_paginated_en(
        &self,
        page: u64,
        per_page: u64,
        is_private: Option<bool>,
    ) -> Result<(Vec<CollectionWithSubjects>, u64), DbErr> {
        let mut query = CollectionEn::find();
        if let Some(private) = is_private {
            query = query.filter(entity::collection_en::Column::IsPrivate.eq(private));
        }
        let collection_pages = query.paginate(&self.db_session, per_page);
        let num_pages = collection_pages.num_pages().await?;
        let collections = collection_pages.fetch_page(page).await?;

        // Fetch subject IDs for each collection
        let mut collections_with_subjects: Vec<CollectionWithSubjects> = Vec::new();
        for collection in collections {
            let subject_ids: Vec<i32> = CollectionEnSubjects::find()
                .filter(entity::collection_en_subjects::Column::CollectionEnId.eq(collection.id))
                .all(&self.db_session)
                .await?
                .into_iter()
                .map(|link| link.subject_en_id)
                .collect();

            collections_with_subjects.push(CollectionWithSubjects {
                collection,
                subject_ids,
            });
        }

        Ok((collections_with_subjects, num_pages))
    }

    async fn list_paginated_ar(
        &self,
        page: u64,
        per_page: u64,
        is_private: Option<bool>,
    ) -> Result<(Vec<CollectionWithSubjects>, u64), DbErr> {
        let mut query = CollectionAr::find();
        if let Some(private) = is_private {
            query = query.filter(entity::collection_ar::Column::IsPrivate.eq(private));
        }
        let collection_pages = query.paginate(&self.db_session, per_page);
        let num_pages = collection_pages.num_pages().await?;
        let collections = collection_pages.fetch_page(page).await?;

        // Fetch subject IDs for each collection and convert to English model
        let mut collections_with_subjects: Vec<CollectionWithSubjects> = Vec::new();
        for collection in collections {
            let subject_ids: Vec<i32> = CollectionArSubjects::find()
                .filter(entity::collection_ar_subjects::Column::CollectionArId.eq(collection.id))
                .all(&self.db_session)
                .await?
                .into_iter()
                .map(|link| link.subject_ar_id)
                .collect();

            // Convert Arabic model to English model
            let en_collection = CollectionEnModel {
                id: collection.id,
                title: collection.title,
                description: collection.description,
                is_private: collection.is_private,
            };

            collections_with_subjects.push(CollectionWithSubjects {
                collection: en_collection,
                subject_ids,
            });
        }

        Ok((collections_with_subjects, num_pages))
    }

    async fn get_one(
        &self,
        id: i32,
        lang: MetadataLanguage,
    ) -> Result<Option<CollectionWithSubjects>, DbErr> {
        match lang {
            MetadataLanguage::English => {
                let collection = CollectionEn::find_by_id(id).one(&self.db_session).await?;

                if let Some(collection) = collection {
                    let subject_ids: Vec<i32> = CollectionEnSubjects::find()
                        .filter(entity::collection_en_subjects::Column::CollectionEnId.eq(id))
                        .all(&self.db_session)
                        .await?
                        .into_iter()
                        .map(|link| link.subject_en_id)
                        .collect();

                    Ok(Some(CollectionWithSubjects {
                        collection,
                        subject_ids,
                    }))
                } else {
                    Ok(None)
                }
            }
            MetadataLanguage::Arabic => {
                let ar_model = CollectionAr::find_by_id(id).one(&self.db_session).await?;

                if let Some(ar) = ar_model {
                    let subject_ids: Vec<i32> = CollectionArSubjects::find()
                        .filter(entity::collection_ar_subjects::Column::CollectionArId.eq(id))
                        .all(&self.db_session)
                        .await?
                        .into_iter()
                        .map(|link| link.subject_ar_id)
                        .collect();

                    let en_collection = CollectionEnModel {
                        id: ar.id,
                        title: ar.title,
                        description: ar.description,
                        is_private: ar.is_private,
                    };

                    Ok(Some(CollectionWithSubjects {
                        collection: en_collection,
                        subject_ids,
                    }))
                } else {
                    Ok(None)
                }
            }
        }
    }

    async fn create_one(
        &self,
        title: String,
        description: Option<String>,
        is_private: bool,
        subject_ids: Vec<i32>,
        lang: MetadataLanguage,
    ) -> Result<i32, DbErr> {
        let txn = self.db_session.begin().await?;

        let collection_id = match lang {
            MetadataLanguage::English => {
                let collection = CollectionEnActiveModel {
                    id: Default::default(),
                    title: ActiveValue::Set(title),
                    description: ActiveValue::Set(description),
                    is_private: ActiveValue::Set(is_private),
                };
                let inserted = collection.save(&txn).await?;
                let id = inserted.try_into_model()?.id;

                let mut subject_links: Vec<CollectionEnSubjectsActiveModel> = vec![];
                for subject_id in subject_ids.iter() {
                    let link = CollectionEnSubjectsActiveModel {
                        collection_en_id: ActiveValue::Set(id),
                        subject_en_id: ActiveValue::Set(*subject_id),
                    };
                    subject_links.push(link);
                }
                if !subject_links.is_empty() {
                    CollectionEnSubjects::insert_many(subject_links)
                        .exec(&txn)
                        .await?;
                }
                id
            }
            MetadataLanguage::Arabic => {
                let collection = CollectionArActiveModel {
                    id: Default::default(),
                    title: ActiveValue::Set(title),
                    description: ActiveValue::Set(description),
                    is_private: ActiveValue::Set(is_private),
                };
                let inserted = collection.save(&txn).await?;
                let id = inserted.try_into_model()?.id;

                let mut subject_links: Vec<CollectionArSubjectsActiveModel> = vec![];
                for subject_id in subject_ids.iter() {
                    let link = CollectionArSubjectsActiveModel {
                        collection_ar_id: ActiveValue::Set(id),
                        subject_ar_id: ActiveValue::Set(*subject_id),
                    };
                    subject_links.push(link);
                }
                if !subject_links.is_empty() {
                    CollectionArSubjects::insert_many(subject_links)
                        .exec(&txn)
                        .await?;
                }
                id
            }
        };

        txn.commit().await?;
        Ok(collection_id)
    }

    async fn update_one(
        &self,
        id: i32,
        title: String,
        description: Option<String>,
        is_private: bool,
        subject_ids: Vec<i32>,
        lang: MetadataLanguage,
    ) -> Result<Option<CollectionWithSubjects>, DbErr> {
        let txn = self.db_session.begin().await?;

        match lang {
            MetadataLanguage::English => {
                let existing = CollectionEn::find_by_id(id).one(&self.db_session).await?;
                if existing.is_none() {
                    return Ok(None);
                }

                let mut collection: CollectionEnActiveModel = existing.unwrap().into();
                collection.title = ActiveValue::Set(title);
                collection.description = ActiveValue::Set(description);
                collection.is_private = ActiveValue::Set(is_private);
                collection.update(&txn).await?;

                // Delete existing subject relationships
                CollectionEnSubjects::delete_many()
                    .filter(entity::collection_en_subjects::Column::CollectionEnId.eq(id))
                    .exec(&txn)
                    .await?;

                // Insert new subject relationships
                let mut subject_links: Vec<CollectionEnSubjectsActiveModel> = vec![];
                for subject_id in subject_ids.iter() {
                    let link = CollectionEnSubjectsActiveModel {
                        collection_en_id: ActiveValue::Set(id),
                        subject_en_id: ActiveValue::Set(*subject_id),
                    };
                    subject_links.push(link);
                }
                if !subject_links.is_empty() {
                    CollectionEnSubjects::insert_many(subject_links)
                        .exec(&txn)
                        .await?;
                }

                txn.commit().await?;

                // Fetch the updated collection with subject IDs
                let collection = CollectionEn::find_by_id(id).one(&self.db_session).await?;

                if let Some(collection) = collection {
                    Ok(Some(CollectionWithSubjects {
                        collection,
                        subject_ids,
                    }))
                } else {
                    Ok(None)
                }
            }
            MetadataLanguage::Arabic => {
                let existing = CollectionAr::find_by_id(id).one(&self.db_session).await?;
                if existing.is_none() {
                    return Ok(None);
                }

                let mut collection: CollectionArActiveModel = existing.unwrap().into();
                collection.title = ActiveValue::Set(title);
                collection.description = ActiveValue::Set(description);
                collection.is_private = ActiveValue::Set(is_private);
                collection.update(&txn).await?;

                // Delete existing subject relationships
                CollectionArSubjects::delete_many()
                    .filter(entity::collection_ar_subjects::Column::CollectionArId.eq(id))
                    .exec(&txn)
                    .await?;

                // Insert new subject relationships
                let mut subject_links: Vec<CollectionArSubjectsActiveModel> = vec![];
                for subject_id in subject_ids.iter() {
                    let link = CollectionArSubjectsActiveModel {
                        collection_ar_id: ActiveValue::Set(id),
                        subject_ar_id: ActiveValue::Set(*subject_id),
                    };
                    subject_links.push(link);
                }
                if !subject_links.is_empty() {
                    CollectionArSubjects::insert_many(subject_links)
                        .exec(&txn)
                        .await?;
                }

                txn.commit().await?;

                // Fetch the updated collection and convert to English model
                let ar_model = CollectionAr::find_by_id(id).one(&self.db_session).await?;

                if let Some(ar) = ar_model {
                    let en_collection = CollectionEnModel {
                        id: ar.id,
                        title: ar.title,
                        description: ar.description,
                        is_private: ar.is_private,
                    };

                    Ok(Some(CollectionWithSubjects {
                        collection: en_collection,
                        subject_ids,
                    }))
                } else {
                    Ok(None)
                }
            }
        }
    }

    async fn delete_one(
        &self,
        id: i32,
        lang: MetadataLanguage,
    ) -> Result<Option<CollectionWithSubjects>, DbErr> {
        match lang {
            MetadataLanguage::English => {
                let collection = CollectionEn::find_by_id(id).one(&self.db_session).await?;

                if collection.is_none() {
                    return Ok(None);
                }

                // Fetch subject IDs before deletion
                let subject_ids: Vec<i32> = CollectionEnSubjects::find()
                    .filter(entity::collection_en_subjects::Column::CollectionEnId.eq(id))
                    .all(&self.db_session)
                    .await?
                    .into_iter()
                    .map(|link| link.subject_en_id)
                    .collect();

                // The collection will be deleted with all its relationships
                // cascading automatically due to ON DELETE CASCADE on the FK constraints.
                CollectionEn::delete_by_id(id)
                    .exec(&self.db_session)
                    .await?;

                Ok(Some(CollectionWithSubjects {
                    collection: collection.unwrap(),
                    subject_ids,
                }))
            }
            MetadataLanguage::Arabic => {
                let collection = CollectionAr::find_by_id(id).one(&self.db_session).await?;

                if collection.is_none() {
                    return Ok(None);
                }

                // Fetch subject IDs before deletion
                let subject_ids: Vec<i32> = CollectionArSubjects::find()
                    .filter(entity::collection_ar_subjects::Column::CollectionArId.eq(id))
                    .all(&self.db_session)
                    .await?
                    .into_iter()
                    .map(|link| link.subject_ar_id)
                    .collect();

                let ar = collection.unwrap();
                let en_collection = CollectionEnModel {
                    id: ar.id,
                    title: ar.title,
                    description: ar.description,
                    is_private: ar.is_private,
                };

                // The collection will be deleted with all its relationships
                // cascading automatically due to ON DELETE CASCADE on the FK constraints.
                CollectionAr::delete_by_id(id)
                    .exec(&self.db_session)
                    .await?;

                Ok(Some(CollectionWithSubjects {
                    collection: en_collection,
                    subject_ids,
                }))
            }
        }
    }
}
