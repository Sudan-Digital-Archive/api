use crate::app_factory::{create_app, AppState};
use crate::config::AppConfig;
use crate::services::accessions_service::AccessionsService;
use crate::services::auth_service::AuthService;
use crate::services::collections_service::CollectionsService;
use crate::services::contributors_service::ContributorsService;
use crate::services::creators_service::CreatorsService;
use crate::services::locations_service::LocationsService;
use crate::services::relations_service::RelationsService;
use crate::services::subjects_service::SubjectsService;
use axum::Router;
use std::sync::Arc;

#[cfg(test)]
mod test_helpers {
    use super::*;
    use crate::auth::JWT_KEYS;
    use crate::models::auth::JWTClaims;
    use crate::repos::collections_repo::CollectionWithSubjects;
    use chrono::{DateTime, Utc};
    use entity::accessions_with_metadata::Model as AccessionsWithMetadataModel;
    use entity::collection_en::Model as CollectionEnModel;
    use entity::dublin_metadata_subject_ar::Model as DublinMetadataSubjectArModel;
    use entity::dublin_metadata_subject_en::Model as DublinMetadataSubjectEnModel;
    use entity::sea_orm_active_enums::Role;
    use jsonwebtoken::{encode, Header};
    use uuid::Uuid;

    pub fn build_test_app() -> Router {
        let accessions_repo = Arc::new(crate::mocks::repos::InMemoryAccessionsRepo::default());
        let auth_repo = Arc::new(crate::mocks::repos::InMemoryAuthRepo::default());
        let browsertrix_repo = Arc::new(crate::mocks::repos::InMemoryBrowsertrixRepo::new());
        let emails_repo = Arc::new(crate::mocks::repos::InMemoryEmailsRepo::default());
        let s3_repo = Arc::new(crate::mocks::repos::InMemoryS3Repo::default());
        let subjects_repo = Arc::new(crate::mocks::repos::InMemorySubjectsRepo::default());
        let locations_repo = Arc::new(crate::mocks::repos::InMemoryLocationsRepo::default());
        let creators_repo = Arc::new(crate::mocks::repos::InMemoryCreatorsRepo::default());
        let contributors_repo = Arc::new(crate::mocks::repos::InMemoryContributorsRepo::default());
        let contributor_roles_repo =
            Arc::new(crate::mocks::repos::InMemoryContributorRolesRepo::default());
        let collections_repo = Arc::new(crate::mocks::repos::InMemoryCollectionsRepo::default());
        let relations_repo = Arc::new(crate::mocks::repos::InMemoryRelationsRepo::default());

        let subjects_service = SubjectsService {
            subjects_repo: subjects_repo.clone(),
        };
        let locations_service = LocationsService {
            locations_repo: locations_repo.clone(),
        };
        let creators_service = CreatorsService {
            creators_repo: creators_repo.clone(),
        };
        let contributors_service = ContributorsService {
            contributors_repo: contributors_repo.clone(),
            contributor_roles_repo: contributor_roles_repo.clone(),
        };
        let relations_service = RelationsService {
            relations_repo: relations_repo.clone(),
        };
        let accessions_service = AccessionsService {
            accessions_repo,
            auth_repo: auth_repo.clone(),
            browsertrix_repo,
            emails_repo,
            s3_repo,
            subjects_service: subjects_service.clone(),
            locations_service: locations_service.clone(),
            creators_service: creators_service.clone(),
            contributors_service: contributors_service.clone(),
            presigned_put_url_expiry_seconds: 900,
            presigned_get_url_expiry_seconds: 3600,
        };
        let auth_service = AuthService {
            auth_repo,
            emails_repo: Arc::new(crate::mocks::repos::InMemoryEmailsRepo::default()),
            jwt_cookie_domain: "test".to_string(),
        };
        let collections_service = CollectionsService {
            collections_repo,
            subjects_repo,
        };
        let app_state = AppState {
            accessions_service,
            auth_service,
            collections_service,
            subjects_service,
            locations_service,
            creators_service,
            contributors_service,
            relations_service,
        };
        let mut app_config = AppConfig::default();
        app_config.max_file_upload_size = 100 * 1024 * 1024;
        create_app(app_state, app_config)
    }

    pub fn build_test_accessions_service() -> AccessionsService {
        let accessions_repo = Arc::new(crate::mocks::repos::InMemoryAccessionsRepo::default());
        let auth_repo = Arc::new(crate::mocks::repos::InMemoryAuthRepo::default());
        let browsertrix_repo = Arc::new(crate::mocks::repos::InMemoryBrowsertrixRepo::new());
        let emails_repo = Arc::new(crate::mocks::repos::InMemoryEmailsRepo::default());
        let s3_repo = Arc::new(crate::mocks::repos::InMemoryS3Repo::default());
        let subjects_service = build_test_subjects_service();
        let locations_service = build_test_locations_service();
        let creators_service = build_test_creators_service();
        let contributors_service = build_test_contributors_service();
        AccessionsService {
            accessions_repo,
            auth_repo,
            browsertrix_repo,
            emails_repo,
            s3_repo,
            subjects_service,
            locations_service,
            creators_service,
            contributors_service,
            presigned_put_url_expiry_seconds: 900,
            presigned_get_url_expiry_seconds: 3600,
        }
    }

    pub fn build_test_auth_service() -> AuthService {
        let auth_repo = Arc::new(crate::mocks::repos::InMemoryAuthRepo::default());
        let emails_repo = Arc::new(crate::mocks::repos::InMemoryEmailsRepo::default());
        AuthService {
            auth_repo,
            emails_repo,
            jwt_cookie_domain: "test".to_string(),
        }
    }

    pub fn build_test_subjects_service() -> SubjectsService {
        let subjects_repo = Arc::new(crate::mocks::repos::InMemorySubjectsRepo::default());
        SubjectsService { subjects_repo }
    }

    pub fn build_test_locations_service() -> LocationsService {
        let locations_repo = Arc::new(crate::mocks::repos::InMemoryLocationsRepo::default());
        LocationsService { locations_repo }
    }

    pub fn build_test_relations_service() -> RelationsService {
        let relations_repo = Arc::new(crate::mocks::repos::InMemoryRelationsRepo::default());
        RelationsService { relations_repo }
    }

    pub fn build_test_creators_service() -> CreatorsService {
        let creators_repo = Arc::new(crate::mocks::repos::InMemoryCreatorsRepo::default());
        CreatorsService { creators_repo }
    }

    pub fn build_test_contributors_service() -> ContributorsService {
        let contributors_repo = Arc::new(crate::mocks::repos::InMemoryContributorsRepo::default());
        let contributor_roles_repo =
            Arc::new(crate::mocks::repos::InMemoryContributorRolesRepo::default());
        ContributorsService {
            contributors_repo,
            contributor_roles_repo,
        }
    }

    pub fn build_test_collections_service() -> CollectionsService {
        let collections_repo = Arc::new(crate::mocks::repos::InMemoryCollectionsRepo::default());
        let subjects_repo = Arc::new(crate::mocks::repos::InMemorySubjectsRepo::default());
        CollectionsService {
            collections_repo,
            subjects_repo,
        }
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
        use entity::accessions_with_metadata::Model as AccessionsWithMetadataModel;
        use entity::sea_orm_active_enums::CrawlStatus;
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
            dublin_metadata_format: entity::sea_orm_active_enums::DublinMetadataFormat::Wacz,
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

    pub fn mock_one_accession() -> entity::accession::Model {
        use entity::accession::Model as AccessionModel;
        use entity::sea_orm_active_enums::CrawlStatus;
        AccessionModel {
            id: 1,
            dublin_metadata_en: Some(1),
            dublin_metadata_ar: Some(2),
            crawl_status: CrawlStatus::Complete,
            crawl_timestamp: Default::default(),
            dublin_metadata_date: Default::default(),
            crawl_id: Some(Default::default()),
            org_id: Some(Default::default()),
            job_run_id: Some("some_job_id".to_string()),
            seed_url: "https://example.com".to_string(),
            is_private: true,
            dublin_metadata_format: entity::sea_orm_active_enums::DublinMetadataFormat::Wacz,
            s3_filename: Some("some_file.wacz".to_string()),
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

    pub fn mock_one_collection() -> entity::collection_en::Model {
        entity::collection_en::Model {
            id: 1,
            title: "Mock Collection".to_string(),
            description: Some("A mock collection for testing".to_string()),
            is_private: false,
        }
    }

    pub fn mock_one_collection_with_subjects() -> CollectionWithSubjects {
        CollectionWithSubjects {
            collection: mock_one_collection(),
            subject_ids: vec![1, 2, 3],
        }
    }

    pub fn mock_paginated_collections(
        page: u64,
        per_page: u64,
    ) -> (Vec<CollectionWithSubjects>, u64) {
        let total_items = 10u64;
        let num_pages = total_items.div_ceil(per_page);
        let items = vec![mock_one_collection_with_subjects()];
        if page >= num_pages {
            return (vec![], num_pages);
        }
        (items, num_pages)
    }

    pub fn mock_paginated_collections_ar(
        page: u64,
        per_page: u64,
    ) -> (Vec<CollectionWithSubjects>, u64) {
        let total_items = 10u64;
        let num_pages = total_items.div_ceil(per_page);
        let items = vec![mock_one_collection_with_subjects()];
        if page >= num_pages {
            return (vec![], num_pages);
        }
        (items, num_pages)
    }
}

#[cfg(test)]
pub use test_helpers::build_test_accessions_service;
#[cfg(test)]
pub use test_helpers::build_test_app;
#[cfg(test)]
pub use test_helpers::build_test_auth_service;
#[cfg(test)]
pub use test_helpers::build_test_collections_service;
#[cfg(test)]
pub use test_helpers::build_test_contributors_service;
#[cfg(test)]
pub use test_helpers::build_test_creators_service;
#[cfg(test)]
pub use test_helpers::build_test_locations_service;
#[cfg(test)]
pub use test_helpers::build_test_relations_service;
#[cfg(test)]
pub use test_helpers::build_test_subjects_service;
#[cfg(test)]
pub use test_helpers::get_mock_jwt;
#[cfg(test)]
pub use test_helpers::mock_one_accession;
#[cfg(test)]
pub use test_helpers::mock_one_accession_with_metadata;
#[cfg(test)]
pub use test_helpers::mock_one_collection;
#[cfg(test)]
pub use test_helpers::mock_one_collection_with_subjects;
#[cfg(test)]
pub use test_helpers::mock_paginated_ar;
#[cfg(test)]
pub use test_helpers::mock_paginated_collections;
#[cfg(test)]
pub use test_helpers::mock_paginated_collections_ar;
#[cfg(test)]
pub use test_helpers::mock_paginated_en;
#[cfg(test)]
pub use test_helpers::mock_paginated_subjects_ar;
#[cfg(test)]
pub use test_helpers::mock_paginated_subjects_en;
