use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum CollectionEn {
    Table,
    IsPublic,
}

#[derive(DeriveIden)]
enum CollectionAr {
    Table,
    IsPublic,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(CollectionEn::Table)
                    .rename_column(CollectionEn::IsPublic, "is_private")
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(CollectionAr::Table)
                    .rename_column(CollectionAr::IsPublic, "is_private")
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(CollectionEn::Table)
                    .rename_column("is_private", "is_public")
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(CollectionAr::Table)
                    .rename_column("is_private", "is_public")
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
