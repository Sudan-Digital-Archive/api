use crate::models::common::MetadataLanguage;
use entity::accessions_with_metadata;
use sea_orm::prelude::Expr;

/// Language-specific column resolution for filtering.
pub struct LanguageColumns {
    /// Column to check for language metadata existence
    pub lang_filter: Expr,
    /// Column containing subject IDs (array)
    pub subjects_column: Expr,
    /// Column containing location ID
    pub locations_column: Expr,
    /// Column containing creator ID
    pub creators_column: Expr,
    /// Column containing contributor IDs (array)
    pub contributors_column: Expr,
    /// Column containing contributor role IDs (array)
    pub contributor_roles_column: Expr,
    /// Full-text search column name
    pub full_text_col: &'static str,
    /// Text search language for tsquery
    pub ts_lang: &'static str,
}

impl LanguageColumns {
    /// Get language-specific columns for filtering.
    pub fn for_language(lang: MetadataLanguage) -> Self {
        match lang {
            MetadataLanguage::English => Self {
                lang_filter: Expr::col(accessions_with_metadata::Column::HasEnglishMetadata),
                subjects_column: Expr::col(accessions_with_metadata::Column::SubjectsEnIds),
                locations_column: Expr::col(accessions_with_metadata::Column::LocationEnId),
                creators_column: Expr::col(accessions_with_metadata::Column::CreatorEnId),
                contributors_column: Expr::col(accessions_with_metadata::Column::ContributorEnIds),
                contributor_roles_column: Expr::col(
                    accessions_with_metadata::Column::ContributorRoleEnIds,
                ),
                full_text_col: "full_text_en",
                ts_lang: "english",
            },
            MetadataLanguage::Arabic => Self {
                lang_filter: Expr::col(accessions_with_metadata::Column::HasArabicMetadata),
                subjects_column: Expr::col(accessions_with_metadata::Column::SubjectsArIds),
                locations_column: Expr::col(accessions_with_metadata::Column::LocationArId),
                creators_column: Expr::col(accessions_with_metadata::Column::CreatorArId),
                contributors_column: Expr::col(accessions_with_metadata::Column::ContributorArIds),
                contributor_roles_column: Expr::col(
                    accessions_with_metadata::Column::ContributorRoleArIds,
                ),
                full_text_col: "full_text_ar",
                ts_lang: "arabic",
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::common::MetadataLanguage;

    #[test]
    fn test_english_columns() {
        let cols = LanguageColumns::for_language(MetadataLanguage::English);
        assert_eq!(cols.full_text_col, "full_text_en");
        assert_eq!(cols.ts_lang, "english");
    }

    #[test]
    fn test_arabic_columns() {
        let cols = LanguageColumns::for_language(MetadataLanguage::Arabic);
        assert_eq!(cols.full_text_col, "full_text_ar");
        assert_eq!(cols.ts_lang, "arabic");
    }
}
