use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        db.execute_unprepared("DROP VIEW IF EXISTS accessions_with_metadata")
            .await?;

        db.execute_unprepared(
            r#"
            CREATE OR REPLACE VIEW accessions_with_metadata AS
            SELECT
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
                a.is_private,
                a.crawl_status,
                a.crawl_timestamp,
                a.crawl_id,
                a.org_id,
                a.job_run_id,
                a.seed_url,
                a.dublin_metadata_date,
                a.dublin_metadata_format,
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
}
