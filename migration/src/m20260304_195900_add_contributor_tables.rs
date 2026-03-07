use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum DublinMetadataContributorEn {
    Table,
    Id,
    Contributor,
}

#[derive(DeriveIden)]
enum DublinMetadataContributorAr {
    Table,
    Id,
    Contributor,
}

#[derive(DeriveIden)]
enum DublinMetadataContributorRoleEn {
    Table,
    Id,
    Role,
}

#[derive(DeriveIden)]
enum DublinMetadataContributorRoleAr {
    Table,
    Id,
    Role,
}

#[derive(DeriveIden)]
enum DublinMetadataEnContributors {
    Table,
    MetadataId,
    ContributorId,
    RoleId,
}

#[derive(DeriveIden)]
enum DublinMetadataArContributors {
    Table,
    MetadataId,
    ContributorId,
    RoleId,
}

#[derive(DeriveIden)]
enum DublinMetadataEn {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum DublinMetadataAr {
    Table,
    Id,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(DublinMetadataContributorEn::Table)
                    .if_not_exists()
                    .col(pk_auto(DublinMetadataContributorEn::Id))
                    .col(string(DublinMetadataContributorEn::Contributor).unique_key())
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(DublinMetadataContributorAr::Table)
                    .if_not_exists()
                    .col(pk_auto(DublinMetadataContributorAr::Id))
                    .col(string(DublinMetadataContributorAr::Contributor).unique_key())
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(DublinMetadataContributorRoleEn::Table)
                    .if_not_exists()
                    .col(pk_auto(DublinMetadataContributorRoleEn::Id))
                    .col(string(DublinMetadataContributorRoleEn::Role).unique_key())
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(DublinMetadataContributorRoleAr::Table)
                    .if_not_exists()
                    .col(pk_auto(DublinMetadataContributorRoleAr::Id))
                    .col(string(DublinMetadataContributorRoleAr::Role).unique_key())
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(DublinMetadataEnContributors::Table)
                    .if_not_exists()
                    .primary_key(
                        Index::create()
                            .name("link_contributors_en")
                            .col(DublinMetadataEnContributors::MetadataId)
                            .col(DublinMetadataEnContributors::ContributorId),
                    )
                    .col(
                        ColumnDef::new(DublinMetadataEnContributors::MetadataId)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DublinMetadataEnContributors::ContributorId)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DublinMetadataEnContributors::RoleId)
                            .integer()
                            .null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("dublin_metadata_contributor_en_metadata")
                            .from(
                                DublinMetadataEnContributors::Table,
                                DublinMetadataEnContributors::MetadataId,
                            )
                            .to(DublinMetadataEn::Table, DublinMetadataEn::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("dublin_metadata_contributor_en_fk")
                            .from(
                                DublinMetadataEnContributors::Table,
                                DublinMetadataEnContributors::ContributorId,
                            )
                            .to(
                                DublinMetadataContributorEn::Table,
                                DublinMetadataContributorEn::Id,
                            ),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("dublin_metadata_contributor_role_en_fk")
                            .from(
                                DublinMetadataEnContributors::Table,
                                DublinMetadataEnContributors::RoleId,
                            )
                            .to(
                                DublinMetadataContributorRoleEn::Table,
                                DublinMetadataContributorRoleEn::Id,
                            ),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(DublinMetadataArContributors::Table)
                    .if_not_exists()
                    .primary_key(
                        Index::create()
                            .name("link_contributors_ar")
                            .col(DublinMetadataArContributors::MetadataId)
                            .col(DublinMetadataArContributors::ContributorId),
                    )
                    .col(
                        ColumnDef::new(DublinMetadataArContributors::MetadataId)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DublinMetadataArContributors::ContributorId)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DublinMetadataArContributors::RoleId)
                            .integer()
                            .null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("dublin_metadata_contributor_ar_metadata")
                            .from(
                                DublinMetadataArContributors::Table,
                                DublinMetadataArContributors::MetadataId,
                            )
                            .to(DublinMetadataAr::Table, DublinMetadataAr::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("dublin_metadata_contributor_ar_fk")
                            .from(
                                DublinMetadataArContributors::Table,
                                DublinMetadataArContributors::ContributorId,
                            )
                            .to(
                                DublinMetadataContributorAr::Table,
                                DublinMetadataContributorAr::Id,
                            ),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("dublin_metadata_contributor_role_ar_fk")
                            .from(
                                DublinMetadataArContributors::Table,
                                DublinMetadataArContributors::RoleId,
                            )
                            .to(
                                DublinMetadataContributorRoleAr::Table,
                                DublinMetadataContributorRoleAr::Id,
                            ),
                    )
                    .to_owned(),
            )
            .await?;

        let db = manager.get_connection();
        db.execute_unprepared("DROP VIEW IF EXISTS accessions_with_metadata")
            .await?;

        db.execute_unprepared(
            r#"
            CREATE OR REPLACE VIEW accessions_with_metadata AS
                a.id,
                a.is_private,
                a.crawl_status,
                a.crawl_timestamp,
                a.crawl_id,
                a.org_id,
                a.job_run_id,
                a.seed_url,
                a.dublin_metadata_date,
                a.dublin_metadata_format,
                a.s3_filename,
                dme.title AS title_en,
                dme.description AS description_en,
                dme.creator_en_id AS creator_en_id,
                dmce.creator AS creator_en,
                dma.title AS title_ar,
                dma.description AS description_ar,
                dma.creator_ar_id AS creator_ar_id,
                dmca.creator AS creator_ar,
                dmle.location AS location_en,
                dmla.location AS location_ar,
                (
                SELECT array_agg(dmse.subject)
                FROM dublin_metadata_subject_en dmse
                LEFT JOIN dublin_metadata_en_subjects dmes ON dmse.id = dmes.subject_id
                LEFT JOIN dublin_metadata_en dme ON dme.id = dmes.metadata_id
                WHERE dme.id = a.dublin_metadata_en
                LIMIT 200
                ) AS subjects_en,
                (
                SELECT array_agg(dmse.id)
                FROM dublin_metadata_subject_en dmse
                LEFT JOIN dublin_metadata_en_subjects dmes ON dmse.id = dmes.subject_id
                LEFT JOIN dublin_metadata_en dme ON dme.id = dmes.metadata_id
                WHERE dme.id = a.dublin_metadata_en
                LIMIT 200
                ) AS subjects_en_ids,
                (
                SELECT array_agg(dmsa.subject)
                FROM dublin_metadata_subject_ar dmsa
                LEFT JOIN dublin_metadata_ar_subjects dmas ON dmsa.id = dmas.subject_id
                LEFT JOIN dublin_metadata_ar dma ON dma.id = dmas.metadata_id
                WHERE dma.id = a.dublin_metadata_ar
                LIMIT 200
                ) AS subjects_ar,
                (
                SELECT array_agg(dmsa.id)
                FROM dublin_metadata_subject_ar dmsa
                LEFT JOIN dublin_metadata_ar_subjects dmas ON dmsa.id = dmas.subject_id
                LEFT JOIN dublin_metadata_ar dma ON dma.id = dmas.metadata_id
                WHERE dma.id = a.dublin_metadata_ar
                LIMIT 200
                ) AS subjects_ar_ids,
                (
                SELECT array_agg(dmcoe.contributor)
                FROM dublin_metadata_contributor_en dmcoe
                LEFT JOIN dublin_metadata_en_contributors dmoec ON dmcoe.id = dmoec.contributor_id
                LEFT JOIN dublin_metadata_en dme2 ON dme2.id = dmoec.metadata_id
                WHERE dme2.id = a.dublin_metadata_en
                LIMIT 200
                ) AS contributors_en,
                (
                SELECT array_agg(COALESCE(dmcre.role, ''))
                FROM dublin_metadata_contributor_role_en dmcre
                LEFT JOIN dublin_metadata_en_contributors dmoec ON dmcre.id = dmoec.role_id
                LEFT JOIN dublin_metadata_en dme2 ON dme2.id = dmoec.metadata_id
                WHERE dme2.id = a.dublin_metadata_en
                LIMIT 200
                ) AS contributor_roles_en,
                (
                SELECT array_agg(dmcoa.contributor)
                FROM dublin_metadata_contributor_ar dmcoa
                LEFT JOIN dublin_metadata_ar_contributors dmoac ON dmcoa.id = dmoac.contributor_id
                LEFT JOIN dublin_metadata_ar dma2 ON dma2.id = dmoac.metadata_id
                WHERE dma2.id = a.dublin_metadata_ar
                LIMIT 200
                ) AS contributors_ar,
                (
                SELECT array_agg(COALESCE(dmcra.role, ''))
                FROM dublin_metadata_contributor_role_ar dmcra
                LEFT JOIN dublin_metadata_ar_contributors dmoac ON dmcra.id = dmoac.role_id
                LEFT JOIN dublin_metadata_ar dma2 ON dma2.id = dmoac.metadata_id
                WHERE dma2.id = a.dublin_metadata_ar
                LIMIT 200
                ) AS contributor_roles_ar,
                COALESCE((dme.id IS NOT NULL), FALSE) AS has_english_metadata,
                COALESCE((dma.id IS NOT NULL), FALSE) AS has_arabic_metadata,
                a.full_text_en,
                a.full_text_ar
            FROM accession a
            LEFT JOIN dublin_metadata_en dme ON a.dublin_metadata_en = dme.id
            LEFT JOIN dublin_metadata_creator_en dmce ON dme.creator_en_id = dmce.id
            LEFT JOIN dublin_metadata_location_en dmle ON dme.location_en_id = dmle.id
            LEFT JOIN dublin_metadata_ar dma ON a.dublin_metadata_ar = dma.id
            LEFT JOIN dublin_metadata_creator_ar dmca ON dma.creator_ar_id = dmca.id
            LEFT JOIN dublin_metadata_location_ar dmla ON dma.location_ar_id = dmla.id
            "#,
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        db.execute_unprepared("DROP VIEW IF EXISTS accessions_with_metadata")
            .await?;

        manager
            .drop_table(
                Table::drop()
                    .table(DublinMetadataEnContributors::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(DublinMetadataArContributors::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(DublinMetadataContributorRoleEn::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(DublinMetadataContributorRoleAr::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(DublinMetadataContributorEn::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(DublinMetadataContributorAr::Table)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
