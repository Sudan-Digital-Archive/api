# Proposal

## Why

Archivists need to archive born-digital files — PDFs today, mp4 and other
formats later — that have no source URL. Today every accession requires a URL:
the crawl endpoint needs one to launch Browsertrix, and the raw upload endpoint
requires `original_url` even though the upload pipeline never uses it. A URL is
only intrinsic to a WACZ capture, which is by definition an archive *of* a URL.
Requiring one for a PDF blocks the archive workflow for files that were never
online.

## What Changes

- Make `original_url` optional on `POST /api/v1/accessions/raw`.
- Require `original_url` only when `metadata_format` is `wacz`; keep URL-format
  validation when a URL is supplied. The rule lives on
  `CreateAccessionRequestRaw` itself (struct-level validation), so every
  consumer that calls `.validate()` — this API, a future MCP server, a Rust
  API client — enforces it identically.
- Make `accession.seed_url` nullable in the database (migration
  `m20261116_212922_nullabel_seed_urls`). Existing rows keep their values;
  no backfill is needed because the column has been `NOT NULL` since creation.
- **BREAKING**: `seed_url` in accession responses becomes `Option<String>` and
  serializes as `null` for accessions without a source URL. No backwards
  compatibility is required at this stage.
- Leave the crawl endpoint unchanged: its `url` is the crawl input and the
  resulting accession is always WACZ.
- `mp4` gains URL-optionality through the same raw path. A future `jpeg`
  format inherits it without further schema work.

## Capabilities

### New Capabilities

- `accession-archiving`: creating accessions from crawls and raw file uploads,
  including per-format source-URL requirements.

### Modified Capabilities

<!-- None: no existing specs in this project yet. -->

## Impact

- **API**: `POST /api/v1/accessions/raw` request gains an optional
  `original_url`; accession responses change `seed_url` to nullable. OpenAPI
  schema updates automatically from the Rust types.
- **Code**: `src/models/request.rs`, `src/models/response.rs`,
  `src/repos/accessions_repo.rs`, `src/routes/accessions.rs` (tests),
  `entity/src/accession.rs`, `entity/src/accessions_with_metadata.rs`,
  `src/mocks/repos/in_memory_accessions_repo.rs`, `src/test_utils.rs`.
- **Database**: `migration/src/m20261116_212922_nullabel_seed_urls.rs`
  (already scaffolded and registered), plus hand-updated entities.
- **Dependencies**: none.
