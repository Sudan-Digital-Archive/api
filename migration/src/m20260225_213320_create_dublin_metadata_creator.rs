use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum DublinMetadataCreatorEn {
    Table,
    Id,
    Creator,
}

#[derive(DeriveIden)]
enum DublinMetadataCreatorAr {
    Table,
    Id,
    Creator,
}

#[derive(DeriveIden)]
enum DublinMetadataEn {
    Table,
    CreatorEnId,
}

#[derive(DeriveIden)]
enum DublinMetadataAr {
    Table,
    CreatorArId,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        db.execute_unprepared("DROP VIEW IF EXISTS accessions_with_metadata")
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(DublinMetadataCreatorEn::Table)
                    .if_not_exists()
                    .col(pk_auto(DublinMetadataCreatorEn::Id))
                    .col(string(DublinMetadataCreatorEn::Creator).unique_key())
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(DublinMetadataCreatorAr::Table)
                    .if_not_exists()
                    .col(pk_auto(DublinMetadataCreatorAr::Id))
                    .col(string(DublinMetadataCreatorAr::Creator).unique_key())
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(DublinMetadataEn::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(DublinMetadataEn::CreatorEnId)
                            .integer()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(DublinMetadataAr::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(DublinMetadataAr::CreatorArId)
                            .integer()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(DublinMetadataEn::Table)
                    .add_foreign_key(
                        TableForeignKey::new()
                            .name("fk_dublin_metadata_en_creator")
                            .from_tbl(DublinMetadataEn::Table)
                            .from_col(DublinMetadataEn::CreatorEnId)
                            .to_tbl(DublinMetadataCreatorEn::Table)
                            .to_col(DublinMetadataCreatorEn::Id)
                            .on_delete(ForeignKeyAction::SetNull)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(DublinMetadataAr::Table)
                    .add_foreign_key(
                        TableForeignKey::new()
                            .name("fk_dublin_metadata_ar_creator")
                            .from_tbl(DublinMetadataAr::Table)
                            .from_col(DublinMetadataAr::CreatorArId)
                            .to_tbl(DublinMetadataCreatorAr::Table)
                            .to_col(DublinMetadataCreatorAr::Id)
                            .on_delete(ForeignKeyAction::SetNull)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        let db = manager.get_connection();
        db.execute_unprepared(
            r#"
            CREATE OR REPLACE VIEW accessions_with_metadata AS
            SELECT
                a.id,
                a.crawl_status,
                a.crawl_timestamp,
                a.crawl_id,
                a.org_id,
                a.job_run_id,
                a.seed_url,
                a.dublin_metadata_date,
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
                COALESCE((dme.id IS NOT NULL), FALSE) AS has_english_metadata,
                COALESCE((dma.id IS NOT NULL), FALSE) AS has_arabic_metadata
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

        db.execute_unprepared(
            r#"
            CREATE OR REPLACE VIEW accessions_with_metadata AS
            SELECT
                a.id,
                a.crawl_status,
                a.crawl_timestamp,
                a.crawl_id,
                a.org_id,
                a.job_run_id,
                a.seed_url,
                a.dublin_metadata_date,
                dme.title AS title_en,
                dme.description AS description_en,
                dma.title AS title_ar,
                dma.description AS description_ar,
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
                COALESCE((dme.id IS NOT NULL), FALSE) AS has_english_metadata,
                COALESCE((dma.id IS NOT NULL), FALSE) AS has_arabic_metadata
            FROM accession a
            LEFT JOIN dublin_metadata_en dme ON a.dublin_metadata_en = dme.id
            LEFT JOIN dublin_metadata_location_en dmle ON dme.location_en_id = dmle.id
            LEFT JOIN dublin_metadata_ar dma ON a.dublin_metadata_ar = dma.id
            LEFT JOIN dublin_metadata_location_ar dmla ON dma.location_ar_id = dmla.id
            "#,
        )
        .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(DublinMetadataEn::Table)
                    .drop_foreign_key("fk_dublin_metadata_en_creator")
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(DublinMetadataAr::Table)
                    .drop_foreign_key("fk_dublin_metadata_ar_creator")
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(DublinMetadataEn::Table)
                    .drop_column(DublinMetadataEn::CreatorEnId)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(DublinMetadataAr::Table)
                    .drop_column(DublinMetadataAr::CreatorArId)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(
                Table::drop()
                    .table(DublinMetadataCreatorEn::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(DublinMetadataCreatorAr::Table)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
