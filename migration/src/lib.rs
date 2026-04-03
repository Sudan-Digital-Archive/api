pub use sea_orm_migration::prelude::*;
mod m20241224_163000_accessions;
mod m20250212_014525_optional_metadata_description;
mod m20250217_012314_subjects_more_like_tags;
mod m20250310_013018_add_auth;
mod m20250712_072835_add_researcher_role;
mod m20250921_203431_add_full_text_search;
mod m20251001_220752_rebuild_full_text_indices;
mod m20251017_164508_add_s3_spaces_filename;
mod m20251111_214709_add_api_keys;
mod m20260105_012142_optional_browsertrix_fields_in_accessions;
mod m20260111_121608_add_contributor_role;
mod m20260206_154024_add_collections_table;
mod m20260222_143347_rename_is_public_to_is_private;
mod m20260224_234743_create_dublin_metadata_location;
mod m20260225_213320_create_dublin_metadata_creator;
mod m20260302_223732_fix_is_private_removal;
mod m20260302_224258_fix_metadata_format_removal;
mod m20260302_224611_fix_s3_filename_removal;
mod m20260304_195826_fix_full_text;
mod m20260304_195900_add_contributor_tables;
mod m20260312_120000_add_dublin_metadata_relations;
mod m20260313_000000_add_filter_ids_to_view;
mod m20260403_162149_fix_view_regression_contributors;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20241224_163000_accessions::Migration),
            Box::new(m20250212_014525_optional_metadata_description::Migration),
            Box::new(m20250217_012314_subjects_more_like_tags::Migration),
            Box::new(m20250310_013018_add_auth::Migration),
            Box::new(m20250712_072835_add_researcher_role::Migration),
            Box::new(m20250921_203431_add_full_text_search::Migration),
            Box::new(m20251001_220752_rebuild_full_text_indices::Migration),
            Box::new(m20251017_164508_add_s3_spaces_filename::Migration),
            Box::new(m20251111_214709_add_api_keys::Migration),
            Box::new(m20260105_012142_optional_browsertrix_fields_in_accessions::Migration),
            Box::new(m20260111_121608_add_contributor_role::Migration),
            Box::new(m20260206_154024_add_collections_table::Migration),
            Box::new(m20260222_143347_rename_is_public_to_is_private::Migration),
            Box::new(m20260224_234743_create_dublin_metadata_location::Migration),
            Box::new(m20260225_213320_create_dublin_metadata_creator::Migration),
            Box::new(m20260302_223732_fix_is_private_removal::Migration),
            Box::new(m20260302_224258_fix_metadata_format_removal::Migration),
            Box::new(m20260302_224611_fix_s3_filename_removal::Migration),
            Box::new(m20260304_195826_fix_full_text::Migration),
            Box::new(m20260304_195900_add_contributor_tables::Migration),
            Box::new(m20260312_120000_add_dublin_metadata_relations::Migration),
            Box::new(m20260313_000000_add_filter_ids_to_view::Migration),
            Box::new(m20260403_162149_fix_view_regression_contributors::Migration),
        ]
    }
}
