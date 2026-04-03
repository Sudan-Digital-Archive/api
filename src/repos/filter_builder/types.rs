use crate::models::common::MetadataLanguage;
use chrono::NaiveDateTime;

/// Filter parameters for building database queries.
#[derive(Debug, Clone, Default)]
pub struct FilterParams {
    pub metadata_language: MetadataLanguage,
    pub metadata_subjects: Option<MetadataIds>,
    pub metadata_locations: Option<Vec<i32>>,
    pub metadata_creators: Option<Vec<i32>>,
    pub metadata_contributors: Option<MetadataIds>,
    pub metadata_contributor_roles: Option<MetadataIds>,
    pub query_term: Option<String>,
    pub url_filter: Option<String>,
    pub date_from: Option<NaiveDateTime>,
    pub date_to: Option<NaiveDateTime>,
    pub is_private: bool,
    pub location: Option<String>,
}

/// Metadata IDs with filter mode for array-based filtering.
/// Used for subjects, contributors, and contributor roles.
///
/// - **Inclusive (`Overlap`):** Match if ANY of the provided IDs exist in the array.
/// - **Exclusive (`Contains`):** Match if ALL of the provided IDs exist in the array.
#[derive(Debug, Clone)]
pub struct MetadataIds {
    pub ids: Vec<i32>,
    pub inclusive_filter: bool,
}
