//! Filter builder module for dynamic query construction across multilingual metadata tables.
//!
//! This module provides functionality to construct dynamic database filters for the digital archive search,
//! supporting multiple languages and search criteria. It's designed to be extensible for future
//! enhancements like full-text search using ts_vector indices and additional metadata fields.
//!
//! # Module Structure
//!
//! - [`types`] - Filter parameters and metadata structures
//! - [`columns`] - Language-specific column resolution
//! - [`filters`] - Individual filter functions
//!
//! # Usage
//!
//! ```rust
//! use crate::repos::filter_builder::{build_filter_expression, FilterParams};
//! use crate::models::common::MetadataLanguage;
//!
//! let params = FilterParams {
//!     metadata_language: MetadataLanguage::English,
//!     metadata_subjects: Some(MetadataIds {
//!         ids: vec![1, 2, 3],
//!         inclusive_filter: true,
//!     }),
//!     ..Default::default()
//! };
//!
//! let filter = build_filter_expression(params);
//! ```

pub mod columns;
pub mod filters;
pub mod types;

pub use columns::LanguageColumns;
pub use filters::{
    apply_contributor_roles_filter, apply_contributors_filter, apply_creators_filter,
    apply_date_range, apply_location_ids_filter, apply_location_text_filter, apply_query_term,
    apply_subjects_filter, apply_url_filter,
};
pub use types::{FilterParams, MetadataIds};

use entity::accessions_with_metadata::Column;
use sea_orm::sea_query::SimpleExpr;
use sea_orm::ColumnTrait;

/// Builds a dynamic filter expression for searching metadata across the archive.
///
/// # Arguments
///
/// * `params` - A struct containing all filter parameters
///
/// # Returns
///
/// * `Option<SimpleExpr>` - SQL expression for filtering, or None if no filters provided
///
/// The function combines these parameters to create appropriate SQL conditions based on
/// which parameters are provided, with proper language-specific handling for metadata fields.
/// It supports full-text search, date range filtering, and subject-based filtering.
///
/// Note that sea orm has no ts vector datatype, so we have to get a bit funky for full text search
pub fn build_filter_expression(params: FilterParams) -> Option<SimpleExpr> {
    let columns = LanguageColumns::for_language(params.metadata_language);
    let columns_ref = &columns;

    // Base expression: language filter + is_private
    let mut expr = Some(
        columns_ref
            .lang_filter
            .clone()
            .eq(true)
            .and(Column::IsPrivate.eq(params.is_private)),
    );

    // Apply query term filter
    if let Some(term) = params.query_term {
        expr = expr.map(|e| apply_query_term(e, &term, columns_ref));
    }

    // Apply date range filter
    expr = expr.map(|e| apply_date_range(e, params.date_from, params.date_to));

    // Apply subjects filter
    if let Some(subjects) = params.metadata_subjects {
        expr =
            expr.map(|e| apply_subjects_filter(e, subjects, columns_ref.subjects_column.clone()));
    }

    // Apply URL filter
    if let Some(url) = params.url_filter {
        expr = expr.map(|e| apply_url_filter(e, &url));
    }

    // Apply location text filter
    if let Some(location) = params.location {
        expr = expr.map(|e| apply_location_text_filter(e, &location, columns_ref));
    }

    // Apply location IDs filter
    if let Some(location_ids) = params.metadata_locations {
        expr = expr.map(|e| {
            apply_location_ids_filter(e, location_ids, columns_ref.locations_column.clone())
        });
    }

    // Apply creators filter
    if let Some(creator_ids) = params.metadata_creators {
        expr = expr
            .map(|e| apply_creators_filter(e, creator_ids, columns_ref.creators_column.clone()));
    }

    // Apply contributors filter
    if let Some(contributors) = params.metadata_contributors {
        expr = expr.map(|e| {
            apply_contributors_filter(e, contributors, columns_ref.contributors_column.clone())
        });
    }

    // Apply contributor roles filter
    if let Some(contributor_roles) = params.metadata_contributor_roles {
        expr = expr.map(|e| {
            apply_contributor_roles_filter(
                e,
                contributor_roles,
                columns_ref.contributor_roles_column.clone(),
            )
        });
    }

    expr
}
