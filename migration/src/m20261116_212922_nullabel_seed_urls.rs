use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Catalog-only change: existing seed_url values are preserved.
        manager
            .alter_table(
                Table::alter()
                    .table(Accession::Table)
                    .modify_column(ColumnDef::new(Accession::SeedUrl).null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        // Backfill NULLs so restoring NOT NULL cannot fail on rows created
        // while the column was nullable.
        db.execute_unprepared("UPDATE accession SET seed_url = '' WHERE seed_url IS NULL")
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Accession::Table)
                    .modify_column(ColumnDef::new(Accession::SeedUrl).not_null())
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Accession {
    Table,
    SeedUrl,
}
