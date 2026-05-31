use crate::app_factory::{build_app, create_app};
use crate::auth::JWT_KEYS;
use crate::config::build_app_config;
use crate::models::auth::JWTClaims;
use crate::repos::collections_repo::CollectionWithSubjects;
use axum::Router;
use chrono::{DateTime, Utc};
use entity::accessions_with_metadata::Model as AccessionsWithMetadataModel;
use entity::collection_en::Model as CollectionEnModel;
use entity::dublin_metadata_subject_ar::Model as DublinMetadataSubjectArModel;
use entity::dublin_metadata_subject_en::Model as DublinMetadataSubjectEnModel;
use entity::sea_orm_active_enums::{CrawlStatus, DublinMetadataFormat, Role};
use jsonwebtoken::{encode, Header};
use uuid::Uuid;

pub async fn create_test_app() -> Router {
    let app_config = build_app_config();
    let (app_state, config) = build_app(&app_config)
        .await
        .expect("building app for tests");
    create_app(app_state, config)
}

pub fn get_mock_jwt() -> String {
    let expiry_time: DateTime<Utc> = Utc::now() + chrono::Duration::hours(24);
    let claims = JWTClaims {
        sub: Uuid::new_v4(),
        exp: expiry_time.timestamp() as usize,
        role: Role::Admin,
    };
    encode(&Header::default(), &claims, &JWT_KEYS.encoding).expect("Failed to encode JWT")
}

pub fn mock_paginated_en() -> (Vec<AccessionsWithMetadataModel>, u64) {
    (vec![mock_one_accession_with_metadata()], 10)
}

pub fn mock_paginated_ar() -> (Vec<AccessionsWithMetadataModel>, u64) {
    (vec![mock_one_accession_with_metadata()], 10)
}

pub fn mock_one_accession_with_metadata() -> AccessionsWithMetadataModel {
    use serde_json::json;
    AccessionsWithMetadataModel {
        id: 1,
        crawl_status: CrawlStatus::Complete,
        crawl_timestamp: Default::default(),
        crawl_id: Some(Default::default()),
        org_id: Some(Default::default()),
        job_run_id: Some("some_job_id".to_string()),
        dublin_metadata_date: Default::default(),
        has_arabic_metadata: true,
        has_english_metadata: true,
        title_en: Some("English Title".to_string()),
        description_en: Some("English Description".to_string()),
        location_en: Some("English Location".to_string()),
        location_en_id: Some(1),
        creator_en_id: Some(1),
        creator_en: Some("English Creator".to_string()),
        title_ar: Some("Arabic Title".to_string()),
        description_ar: Some("Arabic Description".to_string()),
        location_ar: Some("Arabic Location".to_string()),
        location_ar_id: Some(2),
        creator_ar_id: Some(2),
        creator_ar: Some("Arabic Creator".to_string()),
        subjects_en: Some(vec!["archive".to_string()]),
        subjects_ar: Some(vec!["mrhaba archive".to_string()]),
        seed_url: "https://example.com".to_string(),
        subjects_en_ids: Some(vec![1]),
        subjects_ar_ids: Some(vec![3]),
        is_private: true,
        dublin_metadata_format: DublinMetadataFormat::Wacz,
        s3_filename: Some("some_file.wacz".to_string()),
        contributors_en: Some(vec!["Paul McCartney".to_string()]),
        contributor_en_ids: Some(vec![1]),
        contributor_roles_en: Some(vec!["singer".to_string()]),
        contributor_role_en_ids: Some(vec![1]),
        contributors_ar: Some(vec!["بول ماك كارتني".to_string()]),
        contributor_ar_ids: Some(vec![2]),
        contributor_roles_ar: Some(vec!["مغني".to_string()]),
        contributor_role_ar_ids: Some(vec![2]),
        relations_en: Some(
            json!([{"id": 1, "relation_type": "has_part", "related_accession_id": 2}]),
        ),
        relations_ar: Some(
            json!([{"id": 2, "relation_type": "is_part_of", "related_accession_id": 3}]),
        ),
    }
}

pub fn mock_paginated_subjects_en() -> (Vec<DublinMetadataSubjectEnModel>, u64) {
    (
        vec![DublinMetadataSubjectEnModel {
            id: 1,
            subject: "English Subject".to_string(),
        }],
        10,
    )
}

pub fn mock_paginated_subjects_ar() -> (Vec<DublinMetadataSubjectArModel>, u64) {
    (
        vec![DublinMetadataSubjectArModel {
            id: 1,
            subject: "Arabic Subject".to_string(),
        }],
        10,
    )
}
