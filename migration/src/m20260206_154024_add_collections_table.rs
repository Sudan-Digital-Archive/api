use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum CollectionEn {
    Table,
    Id,
    Title,
    Description,
    IsPublic,
}

#[derive(DeriveIden)]
enum CollectionAr {
    Table,
    Id,
    Title,
    Description,
    IsPublic,
}

#[derive(DeriveIden)]
enum CollectionEnSubjects {
    Table,
    CollectionEnId,
    SubjectEnId,
}

#[derive(DeriveIden)]
enum CollectionArSubjects {
    Table,
    CollectionArId,
    SubjectArId,
}

#[derive(DeriveIden)]
enum DublinMetadataSubjectEn {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum DublinMetadataSubjectAr {
    Table,
    Id,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(CollectionEn::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(CollectionEn::Id)
                            .integer()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(CollectionEn::Title).string().not_null())
                    .col(ColumnDef::new(CollectionEn::Description).string().null())
                    .col(ColumnDef::new(CollectionEn::IsPublic).boolean().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(CollectionAr::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(CollectionAr::Id)
                            .integer()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(CollectionAr::Title).string().not_null())
                    .col(ColumnDef::new(CollectionAr::Description).string().null())
                    .col(ColumnDef::new(CollectionAr::IsPublic).boolean().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(CollectionEnSubjects::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(CollectionEnSubjects::CollectionEnId)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CollectionEnSubjects::SubjectEnId)
                            .integer()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(CollectionEnSubjects::CollectionEnId)
                            .col(CollectionEnSubjects::SubjectEnId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_collection_en_subjects_collection_en")
                            .from(
                                CollectionEnSubjects::Table,
                                CollectionEnSubjects::CollectionEnId,
                            )
                            .to(CollectionEn::Table, CollectionEn::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_collection_en_subjects_subject_en")
                            .from(
                                CollectionEnSubjects::Table,
                                CollectionEnSubjects::SubjectEnId,
                            )
                            .to(DublinMetadataSubjectEn::Table, DublinMetadataSubjectEn::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(CollectionArSubjects::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(CollectionArSubjects::CollectionArId)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CollectionArSubjects::SubjectArId)
                            .integer()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(CollectionArSubjects::CollectionArId)
                            .col(CollectionArSubjects::SubjectArId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_collection_ar_subjects_collection_ar")
                            .from(
                                CollectionArSubjects::Table,
                                CollectionArSubjects::CollectionArId,
                            )
                            .to(CollectionAr::Table, CollectionAr::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_collection_ar_subjects_subject_ar")
                            .from(
                                CollectionArSubjects::Table,
                                CollectionArSubjects::SubjectArId,
                            )
                            .to(DublinMetadataSubjectAr::Table, DublinMetadataSubjectAr::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(CollectionArSubjects::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(CollectionEnSubjects::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(CollectionAr::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(CollectionEn::Table).to_owned())
            .await?;
        Ok(())
    }
}
