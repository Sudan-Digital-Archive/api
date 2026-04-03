use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
         manager
            .get_connection()
            .execute_unprepared(
                r#"
                DROP VIEW IF EXISTS accessions_with_metadata
                "#,
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
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
                    dmle.id AS location_en_id,
                    dmla.location AS location_ar,
                    dmla.id AS location_ar_id,
                    (
                    SELECT array_agg(dmse.subject)
                    FROM dublin_metadata_subject_en dmse
                    LEFT JOIN dublin_metadata_en_subjects dmes ON dmse.id = dmes.subject_id
                    LEFT JOIN dublin_metadata_en dme2 ON dme2.id = dmes.metadata_id
                    WHERE dme2.id = a.dublin_metadata_en
                    LIMIT 200
                    ) AS subjects_en,
                    (
                    SELECT array_agg(dmse.id)
                    FROM dublin_metadata_subject_en dmse
                    LEFT JOIN dublin_metadata_en_subjects dmes ON dmse.id = dmes.subject_id
                    LEFT JOIN dublin_metadata_en dme2 ON dme2.id = dmes.metadata_id
                    WHERE dme2.id = a.dublin_metadata_en
                    LIMIT 200
                    ) AS subjects_en_ids,
                    (
                    SELECT array_agg(dmsa.subject)
                    FROM dublin_metadata_subject_ar dmsa
                    LEFT JOIN dublin_metadata_ar_subjects dmas ON dmsa.id = dmas.subject_id
                    LEFT JOIN dublin_metadata_ar dma2 ON dma2.id = dmas.metadata_id
                    WHERE dma2.id = a.dublin_metadata_ar
                    LIMIT 200
                    ) AS subjects_ar,
                    (
                    SELECT array_agg(dmsa.id)
                    FROM dublin_metadata_subject_ar dmsa
                    LEFT JOIN dublin_metadata_ar_subjects dmas ON dmsa.id = dmas.subject_id
                    LEFT JOIN dublin_metadata_ar dma2 ON dma2.id = dmas.metadata_id
                    WHERE dma2.id = a.dublin_metadata_ar
                    LIMIT 200
                    ) AS subjects_ar_ids,
                    (
                    SELECT array_agg(dmcoe.contributor)
                    FROM dublin_metadata_contributor_en dmcoe
                    LEFT JOIN dublin_metadata_en_contributors dmoec ON dmcoe.id = dmoec.contributor_id
                    LEFT JOIN dublin_metadata_en dme3 ON dme3.id = dmoec.metadata_id
                    WHERE dme3.id = a.dublin_metadata_en
                    LIMIT 200
                    ) AS contributors_en,
                    (
                    SELECT array_agg(dmoec.contributor_id)
                    FROM dublin_metadata_en_contributors dmoec
                    WHERE dmoec.metadata_id = a.dublin_metadata_en
                    LIMIT 200
                    ) AS contributor_en_ids,
                    (
                    SELECT array_agg(COALESCE(dmcre.role, ''))
                    FROM dublin_metadata_contributor_role_en dmcre
                    LEFT JOIN dublin_metadata_en_contributors dmoec ON dmcre.id = dmoec.role_id
                    LEFT JOIN dublin_metadata_en dme3 ON dme3.id = dmoec.metadata_id
                    WHERE dme3.id = a.dublin_metadata_en
                    LIMIT 200
                    ) AS contributor_roles_en,     
                    (
                    SELECT array_agg(dmoec.role_id)
                    FROM dublin_metadata_en_contributors dmoec
                    WHERE dmoec.metadata_id = a.dublin_metadata_en
                    LIMIT 200
                    ) AS contributor_role_en_ids,
                    (
                    SELECT array_agg(dmcoa.contributor)
                    FROM dublin_metadata_contributor_ar dmcoa
                    LEFT JOIN dublin_metadata_ar_contributors dmoac ON dmcoa.id = dmoac.contributor_id
                    LEFT JOIN dublin_metadata_ar dma3 ON dma3.id = dmoac.metadata_id
                    WHERE dma3.id = a.dublin_metadata_ar
                    LIMIT 200
                    ) AS contributors_ar,
                    (
                    SELECT array_agg(dmoac.contributor_id)
                    FROM dublin_metadata_ar_contributors dmoac
                    WHERE dmoac.metadata_id = a.dublin_metadata_ar
                    LIMIT 200
                    ) AS contributor_ar_ids,
                    (
                    SELECT array_agg(COALESCE(dmcra.role, ''))
                    FROM dublin_metadata_contributor_role_ar dmcra
                    LEFT JOIN dublin_metadata_ar_contributors dmoac ON dmcra.id = dmoac.role_id
                    LEFT JOIN dublin_metadata_ar dma3 ON dma3.id = dmoac.metadata_id
                    WHERE dma3.id = a.dublin_metadata_ar
                    LIMIT 200
                    ) AS contributor_roles_ar,
                    (
                    SELECT array_agg(dmoac.role_id)
                    FROM dublin_metadata_ar_contributors dmoac
                    WHERE dmoac.metadata_id = a.dublin_metadata_ar
                    LIMIT 200
                    ) AS contributor_role_ar_ids,
                    (
                    SELECT json_agg(
                        json_build_object(
                            'id', dmre.id,
                            'relation_type', dmre.relation_type,
                            'related_accession_id', dmre.related_accession_id
                        )
                    )
                    FROM dublin_metadata_relation_en dmre
                    LEFT JOIN dublin_metadata_en_relations dmer ON dmre.id = dmer.relation_id
                    LEFT JOIN dublin_metadata_en dme4 ON dme4.id = dmer.metadata_id
                    WHERE dme4.id = a.dublin_metadata_en
                    LIMIT 200
                    ) AS relations_en,
                    (
                    SELECT json_agg(
                        json_build_object(
                            'id', dmra.id,
                            'relation_type', dmra.relation_type,
                            'related_accession_id', dmra.related_accession_id
                        )
                    )
                    FROM dublin_metadata_relation_ar dmra
                    LEFT JOIN dublin_metadata_ar_relations dmar ON dmra.id = dmar.relation_id
                    LEFT JOIN dublin_metadata_ar dma4 ON dma4.id = dmar.metadata_id
                    WHERE dma4.id = a.dublin_metadata_ar
                    LIMIT 200
                    ) AS relations_ar,
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
         manager
            .get_connection()
            .execute_unprepared(
                r#"
                DROP VIEW IF EXISTS accessions_with_metadata
                "#,
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
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
                    dmle.id AS location_en_id,
                    dmla.location AS location_ar,
                    dmla.id AS location_ar_id,
                    (
                    SELECT array_agg(dmse.subject)
                    FROM dublin_metadata_subject_en dmse
                    LEFT JOIN dublin_metadata_en_subjects dmes ON dmse.id = dmes.subject_id
                    LEFT JOIN dublin_metadata_en dme2 ON dme2.id = dmes.metadata_id
                    WHERE dme2.id = a.dublin_metadata_en
                    LIMIT 200
                    ) AS subjects_en,
                    (
                    SELECT array_agg(dmse.id)
                    FROM dublin_metadata_subject_en dmse
                    LEFT JOIN dublin_metadata_en_subjects dmes ON dmse.id = dmes.subject_id
                    LEFT JOIN dublin_metadata_en dme2 ON dme2.id = dmes.metadata_id
                    WHERE dme2.id = a.dublin_metadata_en
                    LIMIT 200
                    ) AS subjects_en_ids,
                    (
                    SELECT array_agg(dmsa.subject)
                    FROM dublin_metadata_subject_ar dmsa
                    LEFT JOIN dublin_metadata_ar_subjects dmas ON dmsa.id = dmas.subject_id
                    LEFT JOIN dublin_metadata_ar dma2 ON dma2.id = dmas.metadata_id
                    WHERE dma2.id = a.dublin_metadata_ar
                    LIMIT 200
                    ) AS subjects_ar,
                    (
                    SELECT array_agg(dmsa.id)
                    FROM dublin_metadata_subject_ar dmsa
                    LEFT JOIN dublin_metadata_ar_subjects dmas ON dmsa.id = dmas.subject_id
                    LEFT JOIN dublin_metadata_ar dma2 ON dma2.id = dmas.metadata_id
                    WHERE dma2.id = a.dublin_metadata_ar
                    LIMIT 200
                    ) AS subjects_ar_ids,
                    (
                    SELECT array_agg(dmcoe.contributor)
                    FROM dublin_metadata_contributor_en dmcoe
                    LEFT JOIN dublin_metadata_en_contributors dmoec ON dmcoe.id = dmoec.contributor_id
                    LEFT JOIN dublin_metadata_en dme3 ON dme3.id = dmoec.metadata_id
                    WHERE dme3.id = a.dublin_metadata_en
                    LIMIT 200
                    ) AS contributors_en,
                    (
                    SELECT array_agg(dmcoe.id)
                    FROM dublin_metadata_contributor_en dmcoe
                    LEFT JOIN dublin_metadata_en_contributors dmoec ON dmcoe.id = dmoec.contributor_id
                    LEFT JOIN dublin_metadata_en dme3 ON dme3.id = dmoec.metadata_id
                    WHERE dme3.id = a.dublin_metadata_en
                    LIMIT 200
                    ) AS contributor_en_ids,
                    (
                    SELECT array_agg(COALESCE(dmcre.role, ''))
                    FROM dublin_metadata_contributor_role_en dmcre
                    LEFT JOIN dublin_metadata_en_contributors dmoec ON dmcre.id = dmoec.role_id
                    LEFT JOIN dublin_metadata_en dme3 ON dme3.id = dmoec.metadata_id
                    WHERE dme3.id = a.dublin_metadata_en
                    LIMIT 200
                    ) AS contributor_roles_en,
                    (
                    SELECT array_agg(dmcre.id)
                    FROM dublin_metadata_contributor_role_en dmcre
                    LEFT JOIN dublin_metadata_en_contributors dmoec ON dmcre.id = dmoec.role_id
                    LEFT JOIN dublin_metadata_en dme3 ON dme3.id = dmoec.metadata_id
                    WHERE dme3.id = a.dublin_metadata_en
                    LIMIT 200
                    ) AS contributor_role_en_ids,
                    (
                    SELECT array_agg(dmcoa.contributor)
                    FROM dublin_metadata_contributor_ar dmcoa
                    LEFT JOIN dublin_metadata_ar_contributors dmoac ON dmcoa.id = dmoac.contributor_id
                    LEFT JOIN dublin_metadata_ar dma3 ON dma3.id = dmoac.metadata_id
                    WHERE dma3.id = a.dublin_metadata_ar
                    LIMIT 200
                    ) AS contributors_ar,
                    (
                    SELECT array_agg(dmcoa.id)
                    FROM dublin_metadata_contributor_ar dmcoa
                    LEFT JOIN dublin_metadata_ar_contributors dmoac ON dmcoa.id = dmoac.contributor_id
                    LEFT JOIN dublin_metadata_ar dma3 ON dma3.id = dmoac.metadata_id
                    WHERE dma3.id = a.dublin_metadata_ar
                    LIMIT 200
                    ) AS contributor_ar_ids,
                    (
                    SELECT array_agg(COALESCE(dmcra.role, ''))
                    FROM dublin_metadata_contributor_role_ar dmcra
                    LEFT JOIN dublin_metadata_ar_contributors dmoac ON dmcra.id = dmoac.role_id
                    LEFT JOIN dublin_metadata_ar dma3 ON dma3.id = dmoac.metadata_id
                    WHERE dma3.id = a.dublin_metadata_ar
                    LIMIT 200
                    ) AS contributor_roles_ar,
                    (
                    SELECT array_agg(dmcra.id)
                    FROM dublin_metadata_contributor_role_ar dmcra
                    LEFT JOIN dublin_metadata_ar_contributors dmoac ON dmcra.id = dmoac.role_id
                    LEFT JOIN dublin_metadata_ar dma3 ON dma3.id = dmoac.metadata_id
                    WHERE dma3.id = a.dublin_metadata_ar
                    LIMIT 200
                    ) AS contributor_role_ar_ids,
                    (
                    SELECT json_agg(
                        json_build_object(
                            'id', dmre.id,
                            'relation_type', dmre.relation_type,
                            'related_accession_id', dmre.related_accession_id
                        )
                    )
                    FROM dublin_metadata_relation_en dmre
                    LEFT JOIN dublin_metadata_en_relations dmer ON dmre.id = dmer.relation_id
                    LEFT JOIN dublin_metadata_en dme4 ON dme4.id = dmer.metadata_id
                    WHERE dme4.id = a.dublin_metadata_en
                    LIMIT 200
                    ) AS relations_en,
                    (
                    SELECT json_agg(
                        json_build_object(
                            'id', dmra.id,
                            'relation_type', dmra.relation_type,
                            'related_accession_id', dmra.related_accession_id
                        )
                    )
                    FROM dublin_metadata_relation_ar dmra
                    LEFT JOIN dublin_metadata_ar_relations dmar ON dmra.id = dmar.relation_id
                    LEFT JOIN dublin_metadata_ar dma4 ON dma4.id = dmar.metadata_id
                    WHERE dma4.id = a.dublin_metadata_ar
                    LIMIT 200
                    ) AS relations_ar,
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
}
