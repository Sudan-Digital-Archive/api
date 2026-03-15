use crate::extension::postgres::Type;
use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum DublinMetadataRelationType {
    #[sea_orm(iden = "dublin_metadata_relation_type")]
    Enum,
    HasPart,
    IsPartOf,
    HasVersion,
    IsVersionOf,
    References,
    IsReferencedBy,
    ConformsTo,
    Requires,
}

#[derive(DeriveIden)]
enum DublinMetadataRelationEn {
    Table,
    Id,
    RelationType,
    RelatedAccessionId,
}

#[derive(DeriveIden)]
enum DublinMetadataRelationAr {
    Table,
    Id,
    RelationType,
    RelatedAccessionId,
}

#[derive(DeriveIden)]
enum DublinMetadataEnRelations {
    Table,
    MetadataId,
    RelationId,
}

#[derive(DeriveIden)]
enum DublinMetadataArRelations {
    Table,
    MetadataId,
    RelationId,
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
            .create_type(
                Type::create()
                    .as_enum(DublinMetadataRelationType::Enum)
                    .values([
                        DublinMetadataRelationType::HasPart,
                        DublinMetadataRelationType::IsPartOf,
                        DublinMetadataRelationType::HasVersion,
                        DublinMetadataRelationType::IsVersionOf,
                        DublinMetadataRelationType::References,
                        DublinMetadataRelationType::IsReferencedBy,
                        DublinMetadataRelationType::ConformsTo,
                        DublinMetadataRelationType::Requires,
                    ])
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(DublinMetadataRelationEn::Table)
                    .if_not_exists()
                    .col(pk_auto(DublinMetadataRelationEn::Id))
                    .col(
                        ColumnDef::new(DublinMetadataRelationEn::RelationType)
                            .custom(DublinMetadataRelationType::Enum)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DublinMetadataRelationEn::RelatedAccessionId)
                            .integer()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(DublinMetadataRelationAr::Table)
                    .if_not_exists()
                    .col(pk_auto(DublinMetadataRelationAr::Id))
                    .col(
                        ColumnDef::new(DublinMetadataRelationAr::RelationType)
                            .custom(DublinMetadataRelationType::Enum)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DublinMetadataRelationAr::RelatedAccessionId)
                            .integer()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(DublinMetadataEnRelations::Table)
                    .if_not_exists()
                    .primary_key(
                        Index::create()
                            .name("link_relations_en")
                            .col(DublinMetadataEnRelations::MetadataId)
                            .col(DublinMetadataEnRelations::RelationId),
                    )
                    .col(
                        ColumnDef::new(DublinMetadataEnRelations::MetadataId)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DublinMetadataEnRelations::RelationId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("dublin_metadata_en_relations_metadata")
                            .from(
                                DublinMetadataEnRelations::Table,
                                DublinMetadataEnRelations::MetadataId,
                            )
                            .to(DublinMetadataEn::Table, DublinMetadataEn::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("dublin_metadata_en_relations_relation")
                            .from(
                                DublinMetadataEnRelations::Table,
                                DublinMetadataEnRelations::RelationId,
                            )
                            .to(
                                DublinMetadataRelationEn::Table,
                                DublinMetadataRelationEn::Id,
                            ),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(DublinMetadataArRelations::Table)
                    .if_not_exists()
                    .primary_key(
                        Index::create()
                            .name("link_relations_ar")
                            .col(DublinMetadataArRelations::MetadataId)
                            .col(DublinMetadataArRelations::RelationId),
                    )
                    .col(
                        ColumnDef::new(DublinMetadataArRelations::MetadataId)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DublinMetadataArRelations::RelationId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("dublin_metadata_ar_relations_metadata")
                            .from(
                                DublinMetadataArRelations::Table,
                                DublinMetadataArRelations::MetadataId,
                            )
                            .to(DublinMetadataAr::Table, DublinMetadataAr::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("dublin_metadata_ar_relations_relation")
                            .from(
                                DublinMetadataArRelations::Table,
                                DublinMetadataArRelations::RelationId,
                            )
                            .to(
                                DublinMetadataRelationAr::Table,
                                DublinMetadataRelationAr::Id,
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
                LEFT JOIN dublin_metadata_en dme3 ON dme3.id = dmer.metadata_id
                WHERE dme3.id = a.dublin_metadata_en
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
                LEFT JOIN dublin_metadata_ar dma3 ON dma3.id = dmar.metadata_id
                WHERE dma3.id = a.dublin_metadata_ar
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
        let db = manager.get_connection();
        db.execute_unprepared("DROP VIEW IF EXISTS accessions_with_metadata")
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(DublinMetadataEnRelations::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(DublinMetadataArRelations::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(DublinMetadataRelationEn::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(DublinMetadataRelationAr::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_type(
                Type::drop()
                    .name(DublinMetadataRelationType::Enum)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
