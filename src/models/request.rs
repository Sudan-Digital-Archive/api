//! Request models for the API endpoints.
//!
//! This module contains all the request structures used by the API endpoints,
//! including validation rules for incoming data.

use crate::models::common::{BrowserProfile, MetadataLanguage};
use chrono::NaiveDateTime;
use entity::sea_orm_active_enums::{DublinMetadataFormat, Role};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

/// Request for creating a new accession with crawl + metadata.
#[derive(Debug, Clone, Validate, Deserialize, ToSchema)]
pub struct CreateAccessionRequest {
    #[validate(url)]
    pub url: String,
    pub metadata_language: MetadataLanguage,
    #[validate(length(min = 1, max = 200))]
    pub metadata_title: String,
    #[validate(length(min = 1, max = 2000))]
    pub metadata_description: Option<String>,
    pub metadata_time: NaiveDateTime,
    pub browser_profile: Option<BrowserProfile>,
    #[validate(length(min = 1, max = 200))]
    #[schema(example = json!([1, 2, 3]))]
    pub metadata_subjects: Vec<i32>,
    pub is_private: bool,
    pub metadata_format: DublinMetadataFormat,
    pub s3_filename: Option<String>,
    #[serde(default = "bool::default")]
    pub send_email_notification: bool,
}

/// Request for creating a new accession from raw file + metadata.
#[derive(Validate, Deserialize, ToSchema)]
pub struct CreateAccessionRequestRaw {
    pub metadata_language: MetadataLanguage,
    #[validate(length(min = 1, max = 200))]
    pub metadata_title: String,
    #[validate(length(min = 1, max = 2000))]
    pub metadata_description: Option<String>,
    pub metadata_time: NaiveDateTime,
    #[validate(length(min = 1, max = 200))]
    #[schema(example = json!([1, 2, 3]))]
    pub metadata_subjects: Vec<i32>,
    pub is_private: bool,
    pub metadata_format: DublinMetadataFormat,
    #[validate(url)]
    pub original_url: String,
    pub s3_filename: String,
}

/// Request for creating a new accession from raw file + metadata via multipart upload.
/// The `metadata` field must be the first part and contain the JSON metadata.
/// The `file` field must be the second part and contain the file content.
#[allow(dead_code)]
#[derive(ToSchema)]
pub struct CreateAccessionRawMultipartRequest {
    /// The metadata JSON object.
    #[schema(value_type = CreateAccessionRequestRaw)]
    pub metadata: CreateAccessionRequestRaw,
    /// The file to upload.
    #[schema(value_type = String, format = Binary)]
    pub file: Vec<u8>,
}

/// Request for initiating a new Browsertrix crawl.
#[derive(Debug, Validate, Deserialize, ToSchema)]
pub struct CreateCrawlRequest {
    #[validate(url)]
    pub url: String,
    pub browser_profile: Option<BrowserProfile>,
}

/// Pagination and filtering parameters for listing accessions.
#[derive(Debug, Clone, Deserialize, Validate, IntoParams, ToSchema)]
#[serde(default)]
pub struct AccessionPagination {
    #[schema(default = 0)]
    pub page: u64,
    #[validate(range(min = 1, max = 200))]
    #[schema(default = 20, minimum = 1, maximum = 200)]
    pub per_page: u64,
    pub lang: MetadataLanguage,
    #[schema(example = json!([1, 2, 3]))]
    pub metadata_subjects: Vec<i32>,
    pub metadata_subjects_inclusive_filter: Option<bool>,
    #[validate(length(min = 1, max = 500))]
    pub query_term: Option<String>,
    #[validate(length(min = 1, max = 2000))]
    pub url_filter: Option<String>,
    pub date_from: Option<NaiveDateTime>,
    pub date_to: Option<NaiveDateTime>,
}

impl Default for AccessionPagination {
    fn default() -> Self {
        Self {
            page: 0,
            per_page: 20,
            lang: MetadataLanguage::English,
            metadata_subjects: [].to_vec(),
            metadata_subjects_inclusive_filter: None,
            query_term: None,
            url_filter: None,
            date_from: None,
            date_to: None,
        }
    }
}

/// Pagination and filtering parameters for listing accessions, including private ones.
#[derive(Debug, Clone, Deserialize, Validate, IntoParams, ToSchema)]
#[serde(default)]
pub struct AccessionPaginationWithPrivate {
    #[schema(default = 0)]
    pub page: u64,
    #[validate(range(min = 1, max = 200))]
    #[schema(default = 20, minimum = 1, maximum = 200)]
    pub per_page: u64,
    pub lang: MetadataLanguage,
    #[schema(example = json!([1, 2, 3]))]
    pub metadata_subjects: Vec<i32>,
    pub metadata_subjects_inclusive_filter: Option<bool>,
    #[validate(length(min = 1, max = 500))]
    pub query_term: Option<String>,
    #[validate(length(min = 1, max = 2000))]
    pub url_filter: Option<String>,
    pub date_from: Option<NaiveDateTime>,
    pub date_to: Option<NaiveDateTime>,
    pub is_private: bool,
}

impl Default for AccessionPaginationWithPrivate {
    fn default() -> Self {
        Self {
            page: 0,
            per_page: 20,
            lang: MetadataLanguage::English,
            metadata_subjects: [].to_vec(),
            metadata_subjects_inclusive_filter: None,
            query_term: None,
            url_filter: None,
            date_from: None,
            date_to: None,
            is_private: false,
        }
    }
}

/// Request for creating a new subject category.
#[derive(Debug, Clone, Validate, Deserialize, ToSchema)]
pub struct CreateSubjectRequest {
    #[validate(length(min = 1, max = 100))]
    pub metadata_subject: String,
    pub lang: MetadataLanguage,
}

/// Pagination and filtering parameters for listing subjects.
#[derive(Debug, Clone, Validate, Deserialize, IntoParams, ToSchema)]
#[serde(default)]
pub struct SubjectPagination {
    #[schema(default = 0)]
    pub page: u64,
    #[validate(range(min = 1, max = 200))]
    #[schema(default = 20, minimum = 1, maximum = 200)]
    pub per_page: u64,
    pub lang: MetadataLanguage,
    #[validate(length(min = 1, max = 500))]
    pub query_term: Option<String>,
}

impl Default for SubjectPagination {
    fn default() -> Self {
        Self {
            page: 0,
            per_page: 20,
            lang: MetadataLanguage::English,
            query_term: None,
        }
    }
}

/// Request for creating a new subject category.
#[derive(Debug, Clone, Validate, Deserialize, ToSchema)]
pub struct LoginRequest {
    #[validate(length(min = 1, max = 100))]
    pub email: String,
}

#[derive(Debug, Clone, Validate, Deserialize, ToSchema)]
pub struct AuthorizeRequest {
    pub session_id: Uuid,
    pub user_id: Uuid,
}

#[derive(Debug, Clone, Validate, Deserialize, ToSchema)]
pub struct UpdateAccessionRequest {
    pub metadata_language: MetadataLanguage,
    #[validate(length(min = 1, max = 200))]
    pub metadata_title: String,
    #[validate(length(min = 1, max = 2000))]
    pub metadata_description: Option<String>,
    pub metadata_time: NaiveDateTime,
    #[validate(length(min = 1, max = 200))]
    #[schema(example = json!([1, 2, 3]))]
    pub metadata_subjects: Vec<i32>,
    pub is_private: bool,
}

/// Request for updating a subject category.
#[derive(Debug, Clone, Validate, Deserialize, ToSchema)]
pub struct UpdateSubjectRequest {
    #[validate(length(min = 1, max = 100))]
    pub metadata_subject: String,
    pub lang: MetadataLanguage,
}

/// Request for deleting a subject category.
#[derive(Debug, Clone, Validate, Deserialize, ToSchema)]
pub struct DeleteSubjectRequest {
    pub lang: MetadataLanguage,
}

/// Request for creating a new user (admin only).
#[derive(Debug, Clone, Validate, Deserialize, ToSchema)]
pub struct CreateUserRequest {
    #[validate(length(min = 1, max = 100))]
    pub email: String,
    pub role: Role,
    pub is_active: bool,
}

/// Request for updating a user (admin only, strict PUT semantics).
/// Email cannot be changed.
#[derive(Debug, Clone, Validate, Deserialize, ToSchema)]
pub struct UpdateUserRequest {
    pub role: Role,
    pub is_active: bool,
}

/// Pagination and filtering parameters for listing users.
#[derive(Debug, Clone, Validate, Deserialize, IntoParams, ToSchema)]
#[serde(default)]
pub struct UserPagination {
    #[schema(default = 0)]
    pub page: u64,
    #[validate(range(min = 1, max = 200))]
    #[schema(default = 20, minimum = 1, maximum = 200)]
    pub per_page: u64,
    #[validate(length(min = 1, max = 500))]
    pub email_filter: Option<String>,
}

impl Default for UserPagination {
    fn default() -> Self {
        Self {
            page: 0,
            per_page: 20,
            email_filter: None,
        }
    }
}

/// Request for revoking an API key (admin only).
/// The API key should be provided as received from the user.
#[derive(Debug, Clone, Validate, Deserialize, ToSchema)]
pub struct RevokeApiKeyRequest {
    #[validate(length(min = 1))]
    pub api_key: String,
}

/// Pagination parameters for listing collections (public only).
#[derive(Debug, Clone, Deserialize, Validate, IntoParams, ToSchema)]
#[serde(default)]
pub struct CollectionPagination {
    #[schema(default = 0)]
    pub page: u64,
    #[validate(range(min = 1, max = 200))]
    #[schema(default = 20, minimum = 1, maximum = 200)]
    pub per_page: u64,
    pub lang: MetadataLanguage,
}

impl Default for CollectionPagination {
    fn default() -> Self {
        Self {
            page: 0,
            per_page: 20,
            lang: MetadataLanguage::English,
        }
    }
}

/// Pagination parameters for listing collections with private filter (requires auth).
#[derive(Debug, Clone, Deserialize, Validate, IntoParams, ToSchema)]
#[serde(default)]
pub struct CollectionPaginationWithPrivate {
    #[schema(default = 0)]
    pub page: u64,
    #[validate(range(min = 1, max = 200))]
    #[schema(default = 20, minimum = 1, maximum = 200)]
    pub per_page: u64,
    pub lang: MetadataLanguage,
    pub is_private: Option<bool>,
}

impl Default for CollectionPaginationWithPrivate {
    fn default() -> Self {
        Self {
            page: 0,
            per_page: 20,
            lang: MetadataLanguage::English,
            is_private: None,
        }
    }
}

/// Request for creating a new collection.
#[derive(Debug, Clone, Validate, Deserialize, ToSchema)]
pub struct CreateCollectionRequest {
    pub lang: MetadataLanguage,
    #[validate(length(min = 1, max = 200))]
    pub title: String,
    #[validate(length(min = 1, max = 2000))]
    pub description: Option<String>,
    pub is_public: bool,
    #[validate(length(min = 1, max = 200))]
    #[schema(example = json!([1, 2, 3]))]
    pub subject_ids: Vec<i32>,
}

/// Request for updating an existing collection (idempotent PUT).
#[derive(Debug, Clone, Validate, Deserialize, ToSchema)]
pub struct UpdateCollectionRequest {
    pub lang: MetadataLanguage,
    #[validate(length(min = 1, max = 200))]
    pub title: String,
    #[validate(length(min = 1, max = 2000))]
    pub description: Option<String>,
    pub is_public: bool,
    #[validate(length(min = 1, max = 200))]
    #[schema(example = json!([1, 2, 3]))]
    pub subject_ids: Vec<i32>,
}

/// Query parameters for collection endpoints that require a language specification.
#[derive(Debug, Clone, Deserialize, Validate, IntoParams, ToSchema)]
#[serde(default)]
pub struct CollectionLangParam {
    /// Language for the collection (english or arabic)
    #[schema(default = "english")]
    pub lang: MetadataLanguage,
}

impl Default for CollectionLangParam {
    fn default() -> Self {
        Self {
            lang: MetadataLanguage::English,
        }
    }
}

/// Query parameters for subject endpoints that require a language specification.
#[derive(Debug, Clone, Deserialize, Validate, IntoParams, ToSchema)]
#[serde(default)]
pub struct SubjectLangParam {
    /// Language for the subject (english or arabic)
    #[schema(default = "english")]
    pub lang: MetadataLanguage,
}

impl Default for SubjectLangParam {
    fn default() -> Self {
        Self {
            lang: MetadataLanguage::English,
        }
    }
}
