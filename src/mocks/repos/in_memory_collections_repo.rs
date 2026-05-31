use crate::models::common::MetadataLanguage;
use crate::repos::collections_repo::{CollectionWithSubjects, CollectionsRepo};
use async_trait::async_trait;
use entity::collection_en::Model as CollectionEnModel;
use sea_orm::DbErr;

#[derive(Clone, Debug, Default)]
pub struct InMemoryCollectionsRepo {}

#[async_trait]
impl CollectionsRepo for InMemoryCollectionsRepo {
    async fn list_paginated_en(
        &self,
        _page: u64,
        _per_page: u64,
        _is_private: Option<bool>,
    ) -> Result<(Vec<CollectionWithSubjects>, u64), DbErr> {
        Ok(mock_paginated_collections(0, 10))
    }

    async fn list_paginated_ar(
        &self,
        _page: u64,
        _per_page: u64,
        _is_private: Option<bool>,
    ) -> Result<(Vec<CollectionWithSubjects>, u64), DbErr> {
        Ok(mock_paginated_collections_ar(0, 10))
    }

    async fn get_one(
        &self,
        _id: i32,
        _lang: MetadataLanguage,
    ) -> Result<Option<CollectionWithSubjects>, DbErr> {
        Ok(Some(mock_one_collection_with_subjects()))
    }

    async fn create_one(
        &self,
        _title: String,
        _description: Option<String>,
        _is_private: bool,
        _subject_ids: Vec<i32>,
        _lang: MetadataLanguage,
    ) -> Result<i32, DbErr> {
        Ok(10)
    }

    async fn update_one(
        &self,
        _id: i32,
        _title: String,
        _description: Option<String>,
        _is_private: bool,
        _subject_ids: Vec<i32>,
        _lang: MetadataLanguage,
    ) -> Result<Option<CollectionWithSubjects>, DbErr> {
        Ok(Some(mock_one_collection_with_subjects()))
    }

    async fn delete_one(
        &self,
        _id: i32,
        _lang: MetadataLanguage,
    ) -> Result<Option<CollectionWithSubjects>, DbErr> {
        Ok(Some(mock_one_collection_with_subjects()))
    }
}

fn mock_one_collection() -> CollectionEnModel {
    CollectionEnModel {
        id: 1,
        title: "Mock Collection".to_string(),
        description: Some("A mock collection for testing".to_string()),
        is_private: false,
    }
}

fn mock_one_collection_with_subjects() -> CollectionWithSubjects {
    CollectionWithSubjects {
        collection: mock_one_collection(),
        subject_ids: vec![1, 2, 3],
    }
}

fn mock_paginated_collections(page: u64, per_page: u64) -> (Vec<CollectionWithSubjects>, u64) {
    let total_items = 10u64;
    let num_pages = total_items.div_ceil(per_page);
    let items = vec![mock_one_collection_with_subjects()];
    if page >= num_pages {
        return (vec![], num_pages);
    }
    (items, num_pages)
}

fn mock_paginated_collections_ar(page: u64, per_page: u64) -> (Vec<CollectionWithSubjects>, u64) {
    let total_items = 10u64;
    let num_pages = total_items.div_ceil(per_page);
    let items = vec![mock_one_collection_with_subjects()];
    if page >= num_pages {
        return (vec![], num_pages);
    }
    (items, num_pages)
}
