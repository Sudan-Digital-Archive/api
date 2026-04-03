use sea_orm::sea_query::extension::postgres::PgBinOper;

use super::types::MetadataIds;
use crate::repos::filter_builder::columns::LanguageColumns;
use sea_orm::prelude::Expr;
use sea_orm::sea_query::extension::postgres::PgExpr;
use sea_orm::sea_query::SimpleExpr;
use sea_orm::ColumnTrait;

/// Apply full-text search query term filter.
///
/// Uses PostgreSQL's `plainto_tsquery` for text search on the specified language's
/// full-text index column.
pub fn apply_query_term(expr: SimpleExpr, term: &str, columns: &LanguageColumns) -> SimpleExpr {
    Expr::cust(columns.full_text_col)
        .binary(
            PgBinOper::Matches,
            Expr::cust_with_values(
                format!("plainto_tsquery('{}', $1)", columns.ts_lang),
                [term],
            ),
        )
        .and(expr)
}

/// Apply date range filter to the expression.
///
/// Filters records where `dublin_metadata_date` falls within the specified range.
/// - If only `from` is provided: filters records >= from date
/// - If only `to` is provided: filters records <= to date
/// - If both provided: filters records between from and to (inclusive)
pub fn apply_date_range(
    expr: SimpleExpr,
    from: Option<chrono::NaiveDateTime>,
    to: Option<chrono::NaiveDateTime>,
) -> SimpleExpr {
    use entity::accessions_with_metadata;
    use sea_orm::ColumnTrait;

    let mut result = expr;
    if let Some(from_date) = from {
        result = result.and(accessions_with_metadata::Column::DublinMetadataDate.gte(from_date));
    }
    if let Some(to_date) = to {
        result = result.and(accessions_with_metadata::Column::DublinMetadataDate.lte(to_date));
    }
    result
}

/// Apply subjects filter using PostgreSQL array operators.
///
/// - **Inclusive (`Overlap` `&&`):** Match if ANY of the subject IDs exist in the array.
/// - **Exclusive (`Contains` `@>`):** Match if ALL subject IDs exist in the array.
pub fn apply_subjects_filter(expr: SimpleExpr, subjects: MetadataIds, column: Expr) -> SimpleExpr {
    if subjects.inclusive_filter {
        expr.and(column.binary(PgBinOper::Overlap, subjects.ids))
    } else {
        expr.and(column.binary(PgBinOper::Contains, subjects.ids))
    }
}

/// Apply URL filter using LIKE pattern matching.
///
/// Filters records where `seed_url` starts with the given URL pattern.
pub fn apply_url_filter(expr: SimpleExpr, url: &str) -> SimpleExpr {
    use entity::accessions_with_metadata;
    use sea_orm::ColumnTrait;

    let url_like = format!("{}%", url);
    expr.and(accessions_with_metadata::Column::SeedUrl.like(url_like))
}

/// Apply location text filter using case-insensitive LIKE pattern matching.
///
/// Filters records where the location field (language-specific) contains the search term.
pub fn apply_location_text_filter(
    expr: SimpleExpr,
    location: &str,
    columns: &LanguageColumns,
) -> SimpleExpr {
    use entity::accessions_with_metadata;

    let location_col = if columns.ts_lang == "english" {
        accessions_with_metadata::Column::LocationEn
    } else {
        accessions_with_metadata::Column::LocationAr
    };

    let location_ilike = format!("%{}%", location);
    expr.and(Expr::expr(location_col.into_expr()).ilike(location_ilike))
}

/// Apply location ID filter using OR chain (equivalent to IN clause).
///
/// Filters records where the location ID matches ANY of the provided IDs.
pub fn apply_location_ids_filter(expr: SimpleExpr, ids: Vec<i32>, column: Expr) -> SimpleExpr {
    if ids.is_empty() {
        return expr;
    }

    let in_clause = ids.iter().fold(None, |acc, id| {
        let cond = column.clone().eq(*id);
        match acc {
            None => Some(cond),
            Some(a) => Some(a.or(cond)),
        }
    });

    match in_clause {
        Some(cond) => expr.and(cond),
        None => expr,
    }
}

/// Apply creators filter using OR chain (equivalent to IN clause).
///
/// Filters records where the creator ID matches ANY of the provided IDs.
pub fn apply_creators_filter(expr: SimpleExpr, ids: Vec<i32>, column: Expr) -> SimpleExpr {
    if ids.is_empty() {
        return expr;
    }

    let in_clause = ids.iter().fold(None, |acc, id| {
        let cond = column.clone().eq(*id);
        match acc {
            None => Some(cond),
            Some(a) => Some(a.or(cond)),
        }
    });

    match in_clause {
        Some(cond) => expr.and(cond),
        None => expr,
    }
}

/// Apply contributors filter using PostgreSQL array operators.
///
/// - **Inclusive (`Overlap` `&&`):** Match if ANY contributor ID exists in the array.
/// - **Exclusive (`Contains` `@>`):** Match if ALL contributor IDs exist in the array.
pub fn apply_contributors_filter(
    expr: SimpleExpr,
    contributors: MetadataIds,
    column: Expr,
) -> SimpleExpr {
    if contributors.inclusive_filter {
        expr.and(column.binary(PgBinOper::Overlap, contributors.ids))
    } else {
        expr.and(column.binary(PgBinOper::Contains, contributors.ids))
    }
}

/// Apply contributor roles filter using PostgreSQL array operators.
///
/// - **Inclusive (`Overlap` `&&`):** Match if ANY role ID exists in the array.
/// - **Exclusive (`Contains` `@>`):** Match if ALL role IDs exist in the array.
pub fn apply_contributor_roles_filter(
    expr: SimpleExpr,
    roles: MetadataIds,
    column: Expr,
) -> SimpleExpr {
    if roles.inclusive_filter {
        expr.and(column.binary(PgBinOper::Overlap, roles.ids))
    } else {
        expr.and(column.binary(PgBinOper::Contains, roles.ids))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::common::MetadataLanguage;
    use entity::accessions_with_metadata::Column;
    use sea_orm::sea_query::extension::postgres::PgBinOper;

    #[test]
    fn test_query_term_filter() {
        let columns = LanguageColumns::for_language(MetadataLanguage::English);
        let base = Expr::col(Column::HasEnglishMetadata).eq(true);

        let result = apply_query_term(base, "test", &columns);

        let expected = Expr::cust("full_text_en")
            .binary(
                PgBinOper::Matches,
                Expr::cust_with_values("plainto_tsquery('english', $1)", ["test"]),
            )
            .and(Expr::col(Column::HasEnglishMetadata).eq(true));

        assert_eq!(format!("{:?}", result), format!("{:?}", expected));
    }

    #[test]
    fn test_date_range_both() {
        use chrono::NaiveDate;

        let from_date = NaiveDate::from_ymd_opt(2023, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
        let to_date = NaiveDate::from_ymd_opt(2023, 12, 31)
            .unwrap()
            .and_hms_opt(23, 59, 59)
            .unwrap();

        let base = Expr::col(Column::HasEnglishMetadata).eq(true);
        let result = apply_date_range(base, Some(from_date), Some(to_date));

        assert!(format!("{:?}", result).contains("dublin_metadata_date"));
    }

    #[test]
    fn test_subjects_inclusive() {
        let subjects = MetadataIds {
            ids: vec![1, 2, 3],
            inclusive_filter: true,
        };

        let base = Expr::col(Column::HasEnglishMetadata).eq(true);
        let column = Expr::col(Column::SubjectsEnIds);
        let result = apply_subjects_filter(base, subjects, column);

        assert!(format!("{:?}", result).contains("Overlap"));
    }

    #[test]
    fn test_subjects_exclusive() {
        let subjects = MetadataIds {
            ids: vec![1, 2, 3],
            inclusive_filter: false,
        };

        let base = Expr::col(Column::HasEnglishMetadata).eq(true);
        let column = Expr::col(Column::SubjectsEnIds);
        let result = apply_subjects_filter(base, subjects, column);

        assert!(format!("{:?}", result).contains("Contains"));
    }

    #[test]
    fn test_url_filter() {
        let base = Expr::col(Column::HasEnglishMetadata).eq(true);
        let result = apply_url_filter(base, "https://example.com");

        assert!(format!("{:?}", result).contains("seed_url"));
        assert!(format!("{:?}", result).contains("example.com%"));
    }

    #[test]
    fn test_location_text_filter() {
        let columns = LanguageColumns::for_language(MetadataLanguage::English);
        let base = Expr::col(Column::HasEnglishMetadata).eq(true);
        let result = apply_location_text_filter(base, "Khartoum", &columns);

        assert!(format!("{:?}", result).contains("location_en"));
    }

    #[test]
    fn test_location_ids_filter() {
        let ids = vec![1, 2, 3];
        let base = Expr::col(Column::HasEnglishMetadata).eq(true);
        let column = Expr::col(Column::LocationEnId);
        let result = apply_location_ids_filter(base, ids, column);

        assert!(format!("{:?}", result).contains("location_en_id"));
    }

    #[test]
    fn test_creators_filter() {
        let ids = vec![1, 2, 3];
        let base = Expr::col(Column::HasEnglishMetadata).eq(true);
        let column = Expr::col(Column::CreatorEnId);
        let result = apply_creators_filter(base, ids, column);

        assert!(format!("{:?}", result).contains("creator_en_id"));
    }

    #[test]
    fn test_contributors_inclusive() {
        let contributors = MetadataIds {
            ids: vec![1, 2],
            inclusive_filter: true,
        };

        let base = Expr::col(Column::HasEnglishMetadata).eq(true);
        let column = Expr::col(Column::ContributorEnIds);
        let result = apply_contributors_filter(base, contributors, column);

        assert!(format!("{:?}", result).contains("Overlap"));
    }

    #[test]
    fn test_contributor_roles_exclusive() {
        let roles = MetadataIds {
            ids: vec![1, 2],
            inclusive_filter: false,
        };

        let base = Expr::col(Column::HasEnglishMetadata).eq(true);
        let column = Expr::col(Column::ContributorRoleEnIds);
        let result = apply_contributor_roles_filter(base, roles, column);

        assert!(format!("{:?}", result).contains("Contains"));
    }
}
