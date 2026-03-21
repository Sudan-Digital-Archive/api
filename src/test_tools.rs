//! Test utilities for creating mock implementations and test fixtures.
//! This module provides in-memory implementations of repositories
//! to facilitate testing without requiring actual database or external API connections.

use crate::app_factory::{create_app, AppState};
use crate::auth::JWT_KEYS;
use crate::config::AppConfig;
use crate::models::accessions::AccessionError;
use crate::models::auth::JWTClaims;
use crate::models::common::MetadataLanguage;
use crate::models::request::{
    AccessionPaginationWithPrivate, CreateAccessionRequest, CreateAccessionRequestRaw,
    CreateCrawlRequest,
};
use crate::models::response::CreateCrawlResponse;
use crate::repos::accessions_repo::AccessionsRepo;
use crate::repos::auth_repo::{ApiKeyUserInfo, AuthRepo};
use crate::repos::browsertrix_repo::{BrowsertrixError, BrowsertrixRepo};
use crate::repos::collections_repo::{CollectionWithSubjects, CollectionsRepo};
use crate::repos::contributor_roles_repo::ContributorRolesRepo;
use crate::repos::contributors_repo::ContributorsRepo;
use crate::repos::creators_repo::CreatorsRepo;
use crate::repos::emails_repo::EmailsRepo;
use crate::repos::locations_repo::LocationsRepo;
use crate::repos::relations_repo::RelationsRepo;
use crate::repos::s3_repo::S3Repo;
use crate::repos::subjects_repo::SubjectsRepo;
use crate::services::accessions_service::AccessionsService;
use crate::services::auth_service::AuthService;
use crate::services::collections_service::CollectionsService;
use crate::services::contributors_service::ContributorsService;
use crate::services::creators_service::CreatorsService;
use crate::services::locations_service::LocationsService;
use crate::services::relations_service::RelationsService;
use crate::services::subjects_service::SubjectsService;
use ::entity::sea_orm_active_enums::{DublinMetadataFormat, Role};
use async_trait::async_trait;
use axum::Router;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use entity::accession::Model as AccessionModel;
use entity::accessions_with_metadata::Model as AccessionsWithMetadataModel;
use entity::collection_en::Model as CollectionEnModel;
use entity::dublin_metadata_subject_ar::Model as DublinMetadataSubjectArModel;
use entity::dublin_metadata_subject_en::Model as DublinMetadataSubjectEnModel;
use entity::sea_orm_active_enums::CrawlStatus;
use jsonwebtoken::{encode, Header};
use reqwest::{Error, RequestBuilder, Response};
use sea_orm::DbErr;
use std::error::Error as StdError;
use std::sync::Arc;
use uuid::Uuid;
/// In-memory implementation of AccessionsRepo for testing.
/// Returns predefined mock data instead of interacting with a database.
#[derive(Clone, Debug, Default)]
pub struct InMemoryAccessionsRepo {}

#[async_trait]
impl AccessionsRepo for InMemoryAccessionsRepo {
    /// Mock implementation that always succeeds without storing data.
    async fn write_one(
        &self,
        _create_accession_request: CreateAccessionRequest,
        _org_id: Uuid,
        _crawl_id: Uuid,
        _job_run_id: String,
        _crawl_status: CrawlStatus,
    ) -> Result<i32, DbErr> {
        Ok(10)
    }

    /// Mock implementation for raw accession creation.
    async fn write_one_raw(
        &self,
        _create_accession_request: CreateAccessionRequestRaw,
    ) -> Result<i32, DbErr> {
        Ok(10)
    }

    /// Returns a predefined mock accession.
    async fn get_one(
        &self,
        _id: i32,
        _private: bool,
    ) -> Result<Option<AccessionsWithMetadataModel>, DbErr> {
        Ok(Some(mock_one_accession_with_metadata()))
    }

    /// Returns predefined mock paginated accessions.
    async fn list_paginated(
        &self,
        _params: AccessionPaginationWithPrivate,
    ) -> Result<(Vec<AccessionsWithMetadataModel>, u64), DbErr> {
        Ok(mock_paginated_en())
    }

    async fn delete_one(&self, _id: i32) -> Result<Option<AccessionModel>, AccessionError> {
        Ok(Some(mock_one_accession()))
    }

    async fn update_one(
        &self,
        _id: i32,
        _update_accession_request: crate::models::request::UpdateAccessionRequest,
    ) -> Result<Option<AccessionsWithMetadataModel>, DbErr> {
        Ok(Some(mock_one_accession_with_metadata()))
    }

    async fn get_dublin_metadata_id(
        &self,
        _accession_id: i32,
        _metadata_language: crate::models::common::MetadataLanguage,
    ) -> Result<Option<i32>, DbErr> {
        Ok(Some(1))
    }
}

/// In-memory implementation of SubjectsRepo for testing.
/// Provides mock data for subject-related operations.
#[derive(Clone, Debug, Default)]
pub struct InMemorySubjectsRepo {}

#[async_trait]
impl SubjectsRepo for InMemorySubjectsRepo {
    /// Returns a predefined subject response without storing data.
    async fn write_one(
        &self,
        _create_subject_request: crate::models::request::CreateSubjectRequest,
    ) -> Result<crate::models::response::SubjectResponse, DbErr> {
        Ok(crate::models::response::SubjectResponse {
            id: 1,
            subject: "some cool archive".to_string(),
        })
    }
    async fn delete_one(
        &self,
        _subject_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Option<()>, DbErr> {
        Ok(Some(()))
    }
    /// Returns predefined mock Arabic subjects.
    async fn list_paginated_ar(
        &self,
        _page: u64,
        _per_page: u64,
        _query_term: Option<String>,
        _collection_id: Option<i32>,
    ) -> Result<(Vec<DublinMetadataSubjectArModel>, u64), DbErr> {
        Ok(mock_paginated_subjects_ar())
    }

    /// Returns predefined mock English subjects.
    async fn list_paginated_en(
        &self,
        _page: u64,
        _per_page: u64,
        _query_term: Option<String>,
        _collection_id: Option<i32>,
    ) -> Result<(Vec<DublinMetadataSubjectEnModel>, u64), DbErr> {
        Ok(mock_paginated_subjects_en())
    }

    /// Returns an updated subject response for testing.
    async fn update_one(
        &self,
        _subject_id: i32,
        _update_subject_request: crate::models::request::UpdateSubjectRequest,
    ) -> Result<Option<crate::models::response::SubjectResponse>, DbErr> {
        Ok(Some(crate::models::response::SubjectResponse {
            id: 1,
            subject: "updated subject".to_string(),
        }))
    }

    /// Always returns true for subject verification in tests.
    async fn verify_subjects_exist(
        &self,
        _subject_ids: Vec<i32>,
        _metadata_language: MetadataLanguage,
    ) -> Result<bool, DbErr> {
        Ok(true)
    }

    /// Returns a predefined subject response for testing.
    async fn get_one(
        &self,
        subject_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Option<crate::models::response::SubjectResponse>, DbErr> {
        Ok(Some(crate::models::response::SubjectResponse {
            id: subject_id,
            subject: "Mock Subject".to_string(),
        }))
    }
}

/// In-memory implementation of RelationsRepo for testing.
#[derive(Clone, Debug, Default)]
pub struct InMemoryRelationsRepo {}

#[async_trait]
impl RelationsRepo for InMemoryRelationsRepo {
    async fn write_one(
        &self,
        _metadata_id: i32,
        _relation_type: entity::sea_orm_active_enums::DublinMetadataRelationType,
        _related_accession_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<crate::models::response::RelationResponse, DbErr> {
        Ok(crate::models::response::RelationResponse {
            id: 1,
            relation_type: "has_part".to_string(),
            related_accession_id: 2,
        })
    }

    async fn list(
        &self,
        _metadata_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Vec<crate::models::response::RelationResponse>, DbErr> {
        Ok(vec![crate::models::response::RelationResponse {
            id: 1,
            relation_type: "has_part".to_string(),
            related_accession_id: 2,
        }])
    }

    async fn get_one(
        &self,
        relation_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Option<crate::models::response::RelationResponse>, DbErr> {
        Ok(Some(crate::models::response::RelationResponse {
            id: relation_id,
            relation_type: "has_part".to_string(),
            related_accession_id: 2,
        }))
    }

    async fn delete_one(
        &self,
        _relation_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Option<()>, DbErr> {
        Ok(Some(()))
    }

    async fn verify_related_accessions_exist(
        &self,
        _related_accession_ids: Vec<i32>,
    ) -> Result<bool, DbErr> {
        Ok(true)
    }
}

/// In-memory implementation of CollectionsRepo for testing.
/// Provides mock data for collection-related operations.
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

/// In-memory implementation of LocationsRepo for testing.
#[derive(Clone, Debug, Default)]
pub struct InMemoryLocationsRepo {}

#[async_trait]
impl LocationsRepo for InMemoryLocationsRepo {
    async fn write_one(
        &self,
        create_location_request: crate::models::request::CreateLocationRequest,
    ) -> Result<crate::models::response::LocationResponse, DbErr> {
        let location = match create_location_request.lang {
            MetadataLanguage::English => "Khartoum".to_string(),
            MetadataLanguage::Arabic => "الخرطوم".to_string(),
        };
        Ok(crate::models::response::LocationResponse { id: 1, location })
    }

    async fn list_paginated_ar(
        &self,
        _page: u64,
        _per_page: u64,
        _query_term: Option<String>,
    ) -> Result<(Vec<entity::dublin_metadata_location_ar::Model>, u64), DbErr> {
        Ok((
            vec![entity::dublin_metadata_location_ar::Model {
                id: 1,
                location: "الخرطوم".to_string(),
            }],
            10,
        ))
    }

    async fn list_paginated_en(
        &self,
        _page: u64,
        _per_page: u64,
        _query_term: Option<String>,
    ) -> Result<(Vec<entity::dublin_metadata_location_en::Model>, u64), DbErr> {
        Ok((
            vec![entity::dublin_metadata_location_en::Model {
                id: 1,
                location: "Khartoum".to_string(),
            }],
            10,
        ))
    }

    async fn verify_locations_exist(
        &self,
        _location_ids: Vec<i32>,
        _metadata_language: MetadataLanguage,
    ) -> Result<bool, DbErr> {
        Ok(true)
    }

    async fn update_one(
        &self,
        _location_id: i32,
        _update_location_request: crate::models::request::UpdateLocationRequest,
    ) -> Result<Option<crate::models::response::LocationResponse>, DbErr> {
        Ok(Some(crate::models::response::LocationResponse {
            id: 1,
            location: "updated location".to_string(),
        }))
    }

    async fn delete_one(
        &self,
        _location_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Option<()>, DbErr> {
        Ok(Some(()))
    }

    async fn get_one(
        &self,
        _location_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Option<crate::models::response::LocationResponse>, DbErr> {
        Ok(Some(crate::models::response::LocationResponse {
            id: 1,
            location: "Khartoum".to_string(),
        }))
    }
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryCreatorsRepo {}

#[async_trait]
impl CreatorsRepo for InMemoryCreatorsRepo {
    async fn write_one(
        &self,
        create_creator_request: crate::models::request::CreateCreatorRequest,
    ) -> Result<crate::models::response::CreatorResponse, DbErr> {
        let creator = match create_creator_request.lang {
            MetadataLanguage::English => "Test Creator".to_string(),
            MetadataLanguage::Arabic => "مختبر".to_string(),
        };
        Ok(crate::models::response::CreatorResponse { id: 1, creator })
    }

    async fn list_paginated_ar(
        &self,
        _page: u64,
        _per_page: u64,
        _query_term: Option<String>,
    ) -> Result<(Vec<entity::dublin_metadata_creator_ar::Model>, u64), DbErr> {
        Ok((
            vec![entity::dublin_metadata_creator_ar::Model {
                id: 1,
                creator: "مختبر".to_string(),
            }],
            10,
        ))
    }

    async fn list_paginated_en(
        &self,
        _page: u64,
        _per_page: u64,
        _query_term: Option<String>,
    ) -> Result<(Vec<entity::dublin_metadata_creator_en::Model>, u64), DbErr> {
        Ok((
            vec![entity::dublin_metadata_creator_en::Model {
                id: 1,
                creator: "Test Creator".to_string(),
            }],
            10,
        ))
    }

    async fn verify_creators_exist(
        &self,
        _creator_ids: Vec<i32>,
        _metadata_language: MetadataLanguage,
    ) -> Result<bool, DbErr> {
        Ok(true)
    }

    async fn update_one(
        &self,
        _creator_id: i32,
        _update_creator_request: crate::models::request::UpdateCreatorRequest,
    ) -> Result<Option<crate::models::response::CreatorResponse>, DbErr> {
        Ok(Some(crate::models::response::CreatorResponse {
            id: 1,
            creator: "updated creator".to_string(),
        }))
    }

    async fn delete_one(
        &self,
        _creator_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Option<()>, DbErr> {
        Ok(Some(()))
    }

    async fn get_one(
        &self,
        _creator_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Option<crate::models::response::CreatorResponse>, DbErr> {
        Ok(Some(crate::models::response::CreatorResponse {
            id: 1,
            creator: "Test Creator".to_string(),
        }))
    }
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryContributorsRepo {}

#[async_trait]
impl ContributorsRepo for InMemoryContributorsRepo {
    async fn write_one(
        &self,
        create_contributor_request: crate::models::request::CreateContributorRequest,
    ) -> Result<crate::models::response::ContributorResponse, DbErr> {
        Ok(crate::models::response::ContributorResponse {
            id: 1,
            contributor: create_contributor_request.contributor,
        })
    }

    async fn list_paginated_ar(
        &self,
        _page: u64,
        _per_page: u64,
        _query_term: Option<String>,
    ) -> Result<(Vec<entity::dublin_metadata_contributor_ar::Model>, u64), DbErr> {
        Ok((
            vec![entity::dublin_metadata_contributor_ar::Model {
                id: 1,
                contributor: "مختبر".to_string(),
            }],
            10,
        ))
    }

    async fn list_paginated_en(
        &self,
        _page: u64,
        _per_page: u64,
        _query_term: Option<String>,
    ) -> Result<(Vec<entity::dublin_metadata_contributor_en::Model>, u64), DbErr> {
        Ok((
            vec![entity::dublin_metadata_contributor_en::Model {
                id: 1,
                contributor: "Test Contributor".to_string(),
            }],
            10,
        ))
    }

    async fn verify_contributors_exist(
        &self,
        _contributor_ids: Vec<i32>,
        _metadata_language: MetadataLanguage,
    ) -> Result<bool, DbErr> {
        Ok(true)
    }

    async fn update_one(
        &self,
        _contributor_id: i32,
        update_contributor_request: crate::models::request::UpdateContributorRequest,
    ) -> Result<Option<crate::models::response::ContributorResponse>, DbErr> {
        Ok(Some(crate::models::response::ContributorResponse {
            id: 1,
            contributor: update_contributor_request.contributor,
        }))
    }

    async fn delete_one(
        &self,
        _contributor_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Option<()>, DbErr> {
        Ok(Some(()))
    }

    async fn get_one(
        &self,
        _contributor_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Option<crate::models::response::ContributorResponse>, DbErr> {
        Ok(Some(crate::models::response::ContributorResponse {
            id: 1,
            contributor: "Test Contributor".to_string(),
        }))
    }
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryContributorRolesRepo {}

#[async_trait]
impl ContributorRolesRepo for InMemoryContributorRolesRepo {
    async fn write_one(
        &self,
        create_role_request: crate::models::request::CreateContributorRoleRequest,
    ) -> Result<crate::models::response::ContributorRoleResponse, DbErr> {
        Ok(crate::models::response::ContributorRoleResponse {
            id: 1,
            role: create_role_request.role,
        })
    }

    async fn list_paginated_ar(
        &self,
        _page: u64,
        _per_page: u64,
        _query_term: Option<String>,
    ) -> Result<(Vec<entity::dublin_metadata_contributor_role_ar::Model>, u64), DbErr> {
        Ok((
            vec![entity::dublin_metadata_contributor_role_ar::Model {
                id: 1,
                role: "مختبر دور".to_string(),
            }],
            10,
        ))
    }

    async fn list_paginated_en(
        &self,
        _page: u64,
        _per_page: u64,
        _query_term: Option<String>,
    ) -> Result<(Vec<entity::dublin_metadata_contributor_role_en::Model>, u64), DbErr> {
        Ok((
            vec![entity::dublin_metadata_contributor_role_en::Model {
                id: 1,
                role: "Test Role".to_string(),
            }],
            10,
        ))
    }

    async fn verify_roles_exist(
        &self,
        _role_ids: Vec<i32>,
        _metadata_language: MetadataLanguage,
    ) -> Result<bool, DbErr> {
        Ok(true)
    }

    async fn update_one(
        &self,
        _role_id: i32,
        update_role_request: crate::models::request::UpdateContributorRoleRequest,
    ) -> Result<Option<crate::models::response::ContributorRoleResponse>, DbErr> {
        Ok(Some(crate::models::response::ContributorRoleResponse {
            id: 1,
            role: update_role_request.role,
        }))
    }

    async fn delete_one(
        &self,
        _role_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Option<()>, DbErr> {
        Ok(Some(()))
    }

    async fn get_one(
        &self,
        _role_id: i32,
        _metadata_language: MetadataLanguage,
    ) -> Result<Option<crate::models::response::ContributorRoleResponse>, DbErr> {
        Ok(Some(crate::models::response::ContributorRoleResponse {
            id: 1,
            role: "Test Role".to_string(),
        }))
    }
}

/// In-memory implementation of EmailsRepo for testing.
#[derive(Clone, Debug, Default)]
pub struct InMemoryEmailsRepo {}

#[async_trait]
impl EmailsRepo for InMemoryEmailsRepo {
    async fn send_email(&self, _to: String, _subject: String, _email: String) -> Result<(), Error> {
        Ok(())
    }
}

/// In-memory implementation of AuthRepo for testing.
#[derive(Clone, Debug, Default)]
pub struct InMemoryAuthRepo {}

#[async_trait]
impl AuthRepo for InMemoryAuthRepo {
    async fn get_user_by_email(&self, _email: String) -> Result<Option<Uuid>, DbErr> {
        Ok(Some(Uuid::new_v4()))
    }

    async fn create_session(&self, _user_id: Uuid) -> Result<Uuid, DbErr> {
        Ok(Uuid::new_v4())
    }

    async fn delete_expired_sessions(&self) {
        // No-op for tests
    }

    async fn get_session_expiry(
        &self,
        _authorize_request: crate::models::request::AuthorizeRequest,
    ) -> Result<Option<chrono::NaiveDateTime>, DbErr> {
        Ok(Some(chrono::NaiveDateTime::default()))
    }

    async fn get_one(&self, _user_id: Uuid) -> Result<Option<entity::archive_user::Model>, DbErr> {
        Ok(Some(entity::archive_user::Model {
            id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            role: entity::sea_orm_active_enums::Role::Admin,
            is_active: true,
        }))
    }

    async fn create_api_key_for_user(&self, _user_id: Uuid) -> Result<String, DbErr> {
        Ok("mock_api_key_secret".to_string())
    }

    async fn verify_api_key(&self, _api_key: String) -> Result<Option<ApiKeyUserInfo>, DbErr> {
        Ok(Some(ApiKeyUserInfo {
            user_id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            role: Role::Admin,
        }))
    }

    async fn delete_expired_api_keys(&self) {
        // No-op for tests
    }

    async fn create_user(
        &self,
        email: String,
        role: entity::sea_orm_active_enums::Role,
        is_active: bool,
    ) -> Result<entity::archive_user::Model, DbErr> {
        Ok(entity::archive_user::Model {
            id: Uuid::new_v4(),
            email,
            role,
            is_active,
        })
    }

    async fn update_user(
        &self,
        user_id: Uuid,
        role: entity::sea_orm_active_enums::Role,
        is_active: bool,
    ) -> Result<Option<entity::archive_user::Model>, DbErr> {
        Ok(Some(entity::archive_user::Model {
            id: user_id,
            email: "updated@example.com".to_string(),
            role,
            is_active,
        }))
    }

    async fn get_user_by_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<entity::archive_user::Model>, DbErr> {
        Ok(Some(entity::archive_user::Model {
            id: user_id,
            email: "test@example.com".to_string(),
            role: entity::sea_orm_active_enums::Role::Researcher,
            is_active: true,
        }))
    }

    async fn list_users(
        &self,
        _page: u64,
        _per_page: u64,
        _email_filter: Option<String>,
    ) -> Result<(Vec<entity::archive_user::Model>, u64), DbErr> {
        Ok((
            vec![entity::archive_user::Model {
                id: Uuid::new_v4(),
                email: "test@example.com".to_string(),
                role: entity::sea_orm_active_enums::Role::Researcher,
                is_active: true,
            }],
            1,
        ))
    }

    async fn delete_user(&self, _user_id: Uuid) -> Result<Option<()>, DbErr> {
        Ok(Some(()))
    }

    async fn revoke_api_key(&self, _key_hash: String, _user_id: Uuid) -> Result<Option<()>, DbErr> {
        // For tests, always return Some(()) to indicate success
        // This simulates finding and revoking an API key
        Ok(Some(()))
    }
}

/// In-memory implementation of BrowsertrixRepo for testing.
/// Mocks interactions with the Browsertrix API.
pub struct InMemoryBrowsertrixRepo {}

#[async_trait]
impl BrowsertrixRepo for InMemoryBrowsertrixRepo {
    /// Returns a random UUID as organization ID.
    fn get_org_id(&self) -> Uuid {
        Uuid::new_v4()
    }

    /// Mock refresh authentication that does nothing.
    async fn refresh_auth(&self) {
        // No-op for tests
    }

    /// Returns a fixed mock URL for WACZ files.
    async fn get_wacz_url(&self, _job_run_id: &str) -> Result<String, BrowsertrixError> {
        Ok("my url".to_owned())
    }

    /// Returns a mock stream for WACZ file content.
    async fn download_wacz_stream(&self, _crawl_id: &str) -> Result<Response, BrowsertrixError> {
        Ok(Response::from(http::Response::new("{}")))
    }

    /// Returns a mock response for any request.
    async fn make_request(&self, _req: RequestBuilder) -> Result<Response, BrowsertrixError> {
        Ok(reqwest::Response::from(http::Response::new(
            "mock test data",
        )))
    }

    /// Returns a fixed authentication token.
    async fn authenticate(&self) -> Result<String, BrowsertrixError> {
        Ok("test_token".to_string())
    }

    /// Mock initialization that does nothing.
    async fn initialize(&mut self) {
        // No-op for tests
    }

    /// Returns a mock crawl response with random UUID and fixed job ID.
    async fn create_crawl(
        &self,
        _create_crawl_request: CreateCrawlRequest,
    ) -> Result<CreateCrawlResponse, BrowsertrixError> {
        Ok(CreateCrawlResponse {
            id: Uuid::new_v4(),
            run_now_job: "test_job_123".to_string(),
        })
    }

    /// Returns a fixed "complete" status for any crawl.
    async fn get_crawl_status(&self, _crawl_id: Uuid) -> Result<String, BrowsertrixError> {
        Ok("complete".to_owned())
    }
}
/// Mock implementation for testing
#[derive(Debug, Clone, Default)]
pub struct InMemoryS3Repo {
    #[allow(dead_code)]
    pub bucket: String,
}

#[async_trait]
impl S3Repo for InMemoryS3Repo {
    async fn new(
        bucket: String,
        _endpoint_url: &str,
        _access_key: &str,
        _secret_key: &str,
        _operation_timeout: u64,
        _operation_attempt_timeout: u64,
        _connect_timeout: u64,
    ) -> Result<Self, Box<dyn StdError>> {
        Ok(Self { bucket })
    }

    async fn upload_from_bytes(
        &self,
        key: &str,
        _bytes: Bytes,
        _content_type: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        // Return a deterministic mock ETag based on the key
        Ok(format!("mock-etag-{}", key))
    }

    async fn get_presigned_url(
        &self,
        _object_key: &str,
        _expires_in: u64,
    ) -> Result<String, Box<dyn StdError>> {
        Ok("my url".to_string())
    }

    async fn initiate_multipart_upload(
        &self,
        key: &str,
        _content_type: &str,
    ) -> Result<String, Box<dyn StdError>> {
        Ok(format!("mock-upload-id-{}", key))
    }

    async fn upload_part(
        &self,
        _key: &str,
        _upload_id: &str,
        part_number: i32,
        _bytes: Bytes,
    ) -> Result<(String, i32), Box<dyn StdError>> {
        Ok((format!("mock-etag-part-{}", part_number), part_number))
    }

    async fn complete_multipart_upload(
        &self,
        key: &str,
        _upload_id: &str,
        _parts: Vec<(String, i32)>,
    ) -> Result<String, Box<dyn StdError>> {
        Ok(format!("mock-final-etag-{}", key))
    }

    async fn delete_object(&self, _key: &str) -> Result<(), Box<dyn StdError>> {
        Ok(())
    }
}
/// Builds a test accessions service with in-memory repositories.
/// Useful for unit testing service functionality without database connections.
pub fn build_test_accessions_service() -> AccessionsService {
    let accessions_repo = Arc::new(InMemoryAccessionsRepo::default());
    let auth_repo = Arc::new(InMemoryAuthRepo::default());
    let browsertrix_repo = Arc::new(InMemoryBrowsertrixRepo {});
    let emails_repo = Arc::new(InMemoryEmailsRepo::default());
    let s3_repo = Arc::new(InMemoryS3Repo {
        bucket: "test-bucket".to_string(),
    });
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
    }
}

pub fn build_test_auth_service() -> AuthService {
    let auth_repo = Arc::new(InMemoryAuthRepo::default());
    let emails_repo = Arc::new(InMemoryEmailsRepo::default());

    AuthService {
        auth_repo,
        emails_repo,
        jwt_cookie_domain: "test".to_string(),
    }
}

/// Builds a test subjects service with in-memory repository.
pub fn build_test_subjects_service() -> SubjectsService {
    let subjects_repo = Arc::new(InMemorySubjectsRepo::default());
    SubjectsService { subjects_repo }
}

/// Builds a test locations service with in-memory repository.
pub fn build_test_locations_service() -> LocationsService {
    let locations_repo = Arc::new(InMemoryLocationsRepo::default());
    LocationsService { locations_repo }
}

/// Builds a test relations service with in-memory repository.
pub fn build_test_relations_service() -> RelationsService {
    let relations_repo = Arc::new(InMemoryRelationsRepo::default());
    RelationsService { relations_repo }
}

/// Builds a test creators service with in-memory repository.
pub fn build_test_creators_service() -> CreatorsService {
    let creators_repo = Arc::new(InMemoryCreatorsRepo::default());
    CreatorsService { creators_repo }
}

/// Builds a test contributors service with in-memory repository.
pub fn build_test_contributors_service() -> ContributorsService {
    let contributors_repo = Arc::new(InMemoryContributorsRepo::default());
    let contributor_roles_repo = Arc::new(InMemoryContributorRolesRepo::default());
    ContributorsService {
        contributors_repo,
        contributor_roles_repo,
    }
}

/// Builds a test collections service with in-memory repositories.
pub fn build_test_collections_service() -> CollectionsService {
    let collections_repo = Arc::new(InMemoryCollectionsRepo::default());
    let subjects_repo = Arc::new(InMemorySubjectsRepo::default());
    CollectionsService {
        collections_repo,
        subjects_repo,
    }
}

/// Creates a test application instance with in-memory services.
/// The returned Router can be used with axum test utilities.
pub fn build_test_app() -> Router {
    let accessions_service = build_test_accessions_service();
    let collections_service = build_test_collections_service();
    let subjects_service = build_test_subjects_service();
    let locations_service = build_test_locations_service();
    let creators_service = build_test_creators_service();
    let contributors_service = build_test_contributors_service();
    let auth_service = build_test_auth_service();
    let relations_service = build_test_relations_service();
    let app_state = AppState {
        accessions_service,
        collections_service,
        subjects_service,
        locations_service,
        creators_service,
        contributors_service,
        auth_service,
        relations_service,
    };
    let mut app_config = AppConfig::default();
    app_config.max_file_upload_size = 100 * 1024 * 1024;
    create_app(app_state, app_config, true)
}

/// Creates a mock paginated collection of English accessions.
pub fn mock_paginated_en() -> (Vec<AccessionsWithMetadataModel>, u64) {
    (vec![mock_one_accession_with_metadata()], 10)
}

/// Creates a mock paginated collection of Arabic accessions.
pub fn mock_paginated_ar() -> (Vec<AccessionsWithMetadataModel>, u64) {
    (vec![mock_one_accession_with_metadata()], 10)
}

/// Creates a single mock accession with metadata for testing.
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
        creator_en_id: Some(1),
        creator_en: Some("English Creator".to_string()),
        title_ar: Some("Arabic Title".to_string()),
        description_ar: Some("Arabic Description".to_string()),
        location_ar: Some("Arabic Location".to_string()),
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
        contributor_roles_en: Some(vec!["singer".to_string()]),
        contributors_ar: Some(vec!["بول ماك كارتني".to_string()]),
        contributor_roles_ar: Some(vec!["مغني".to_string()]),
        relations_en: Some(
            json!([{"id": 1, "relation_type": "has_part", "related_accession_id": 2}]),
        ),
        relations_ar: Some(
            json!([{"id": 2, "relation_type": "is_part_of", "related_accession_id": 3}]),
        ),
    }
}

pub fn mock_one_accession() -> AccessionModel {
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
        dublin_metadata_format: DublinMetadataFormat::Wacz,
        s3_filename: Some("some_file.wacz".to_string()),
    }
}

/// Creates a collection of mock English subjects for testing.
pub fn mock_paginated_subjects_en() -> (Vec<DublinMetadataSubjectEnModel>, u64) {
    (
        vec![DublinMetadataSubjectEnModel {
            id: 1,
            subject: "English Subject".to_string(),
        }],
        10,
    )
}

/// Creates a collection of mock Arabic subjects for testing.
pub fn mock_paginated_subjects_ar() -> (Vec<DublinMetadataSubjectArModel>, u64) {
    (
        vec![DublinMetadataSubjectArModel {
            id: 1,
            subject: "Arabic Subject".to_string(),
        }],
        10,
    )
}

pub fn get_mock_jwt() -> String {
    let expiry_time: DateTime<Utc> = Utc::now() + chrono::Duration::hours(24);
    let claims = JWTClaims {
        sub: Uuid::new_v4(),
        exp: expiry_time.timestamp() as usize,
        role: Role::Admin,
    };
    let jwt =
        encode(&Header::default(), &claims, &JWT_KEYS.encoding).expect("Failed to encode JWT");
    jwt
}

/// Creates a mock paginated collection of English collections.
pub fn mock_paginated_collections(page: u64, per_page: u64) -> (Vec<CollectionWithSubjects>, u64) {
    let total_items = 10u64;
    let num_pages = (total_items + per_page - 1) / per_page;
    let items = vec![mock_one_collection_with_subjects()];
    // Return only items for the requested page
    if page >= num_pages {
        return (vec![], num_pages);
    }
    (items, num_pages)
}

/// Creates a mock paginated collection of Arabic collections.
pub fn mock_paginated_collections_ar(
    page: u64,
    per_page: u64,
) -> (Vec<CollectionWithSubjects>, u64) {
    let total_items = 10u64;
    let num_pages = (total_items + per_page - 1) / per_page;
    // Arabic collections return the same structure (CollectionWithSubjects uses CollectionEnModel)
    let items = vec![mock_one_collection_with_subjects()];
    // Return only items for the requested page
    if page >= num_pages {
        return (vec![], num_pages);
    }
    (items, num_pages)
}

/// Creates a single mock English collection for testing.
pub fn mock_one_collection() -> CollectionEnModel {
    CollectionEnModel {
        id: 1,
        title: "Mock Collection".to_string(),
        description: Some("A mock collection for testing".to_string()),
        is_private: false,
    }
}

/// Creates a single mock collection with subjects for testing.
pub fn mock_one_collection_with_subjects() -> CollectionWithSubjects {
    CollectionWithSubjects {
        collection: mock_one_collection(),
        subject_ids: vec![1, 2, 3],
    }
}
