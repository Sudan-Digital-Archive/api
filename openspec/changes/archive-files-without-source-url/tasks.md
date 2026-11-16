# Tasks

## 1. Database migration

- [x] 1.1 Replace the scaffold in `migration/src/m20261116_212922_nullabel_seed_urls.rs` with `ALTER TABLE accession ALTER COLUMN seed_url DROP NOT NULL` in `up`, and verify against the local compose database that `\d accession` reports `seed_url` nullable and existing rows retain their values (row count and a sample value unchanged before/after)
- [x] 1.2 Implement `down` as backfill (`UPDATE accession SET seed_url = '' WHERE seed_url IS NULL`) followed by `SET NOT NULL`, and verify an up → down → up round-trip succeeds on the compose database after inserting a NULL row

## 2. Entities (hand-updated, no codegen)

- [x] 2.1 Change `seed_url` to `Option<String>` in `entity/src/accession.rs` and verify `cargo check -p entity` passes
- [x] 2.2 Change `seed_url` to `Option<String>` in `entity/src/accessions_with_metadata.rs` and verify `cargo check -p entity` passes

## 3. Request model and validation

- [x] 3.1 Change `CreateAccessionRequestRaw.original_url` to `Option<String>` (keeping `#[validate(url)]`, which skips `None`) and verify unit tests cover: absent URL accepted, valid URL accepted, malformed URL rejected
- [x] 3.2 Add the struct-level `#[validate(schema(function = "validate_wacz_requires_original_url"))]` rule to `CreateAccessionRequestRaw` and verify unit tests cover: `wacz` + no URL fails under `__all__`, `wacz` + valid URL passes, `pdf`/`mp4` + no URL passes

## 4. Repository layer

- [x] 4.1 Change `CreateAccessionData.seed_url` to `Option<String>`, set `Some(url)` in `write_one`, and pass `original_url` through in `write_one_raw`, verifying with the existing repo tests

## 5. Response contract

- [x] 5.1 Change `AccessionsWithMetadataResponse.seed_url` to `Option<String>` and verify a serialization test emits `"seed_url": null` for a URL-less accession

## 6. Mocks, fixtures, and route tests

- [x] 6.1 Update `src/mocks/repos/in_memory_accessions_repo.rs` fixtures and `src/test_utils.rs` to `Some(...)`, verifying the mocked test suite still passes
- [x] 6.2 Add route tests in `src/routes/accessions.rs`: raw `pdf` without `original_url` returns 201, raw `wacz` without `original_url` returns 400, raw `pdf` with a malformed URL returns 400, verifying with the mocked test run

## 7. Integration verification

- [x] 7.1 Run `cargo fmt -- --check`, `cargo clippy -- -D warnings`, and the full test suite with the mock env flags from AGENTS.md, verifying all pass
- [x] 7.2 Manually verify end to end against the compose database: create a `pdf` accession without a URL (201, then `GET` shows `"seed_url": null`) and a `wacz` accession without a URL (400) — waived by user; covered by the mocked route tests for the same three cases plus the real-database migration verification

## Workflow follow-up

- Archive the change after review requirements are satisfied.
- Verify the archived spec at `openspec/specs/accession-archiving/spec.md`.
