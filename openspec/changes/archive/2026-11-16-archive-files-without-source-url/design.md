# Design

## Context

See `proposal.md` for motivation and `specs/accession-archiving/spec.md` for the
behavior contract.

Relevant current state:

- `accession.seed_url` is `TEXT NOT NULL`; the `accessions_with_metadata` view
  passes it through unchanged.
- `POST /accessions/raw` requires `original_url: String`; the raw upload
  pipeline never uses it — it only lands in `seed_url` as provenance.
- `POST /accessions/crawl` requires `url` as the crawl input and hardcodes
  `DublinMetadataFormat::Wacz`.
- The route calls `payload.validate()` before delegating to the service, and the
  service performs DB-backed reference checks (`validate_metadata_references`).
- `validator` 0.19 is already a dependency.

## Goals / Non-Goals

**Goals:**

- Make the absence of a source URL a first-class state: `NULL` in the database,
  `None` in Rust, `null` in JSON.
- Put the "WACZ requires a URL" rule on the request model so every consumer of
  the model enforces it identically.
- Keep the crawl path behavior unchanged.

**Non-Goals:**

- Adding `jpeg` (or other formats) — future work that inherits this design.
- Removing WACZ from the raw upload endpoint.
- Backwards compatibility for the response contract.
- Running sea-orm entity codegen — entities are hand-updated.

## Decisions

### 1. Nullable column, not an empty-string sentinel

`seed_url` becomes `TEXT NULL`. `NULL` is Postgres's native "value absent";
`Option<String>` forces every Rust consumer to handle the missing case at
compile time, and JSON `null` is unambiguous to clients.

*Alternative rejected:* keep `NOT NULL` and store `''`. It avoids type changes
but leaves the schema asserting a constraint the domain no longer has, relies on
every consumer remembering `.is_empty()`, and makes `""` ambiguous in responses.

### 2. Conditional rule on the request model

`CreateAccessionRequestRaw` gets a struct-level schema function:

```rust
#[validate(schema(function = "validate_wacz_requires_original_url"))]
```

The function returns `Result<(), ValidationError>` and compares
`metadata_format` with `DublinMetadataFormat::Wacz` and checks
`original_url.is_none()`. Verified against `validator_derive` 0.19: the schema
function is called with `&self` and its error lands under `__all__`, so the
existing `payload.validate()` call already surfaces it as a 400.

*Alternatives rejected:* a service-layer check (only covers this API — the
future MCP server and Rust client would bypass it) and a hand-written `Validate`
impl (abandons the declarative pattern used by every other model).

### 3. Model validation stays pure; DB checks stay in the service

Model-level rules must not touch I/O so they remain portable when the models are
extracted to a shared crate for the MCP server and client. The WACZ/URL rule is
pure (two fields, no lookups). `validate_metadata_references` remains in the
service because it queries the database.

### 4. Migration is constraint-only

- Up: `ALTER TABLE accession ALTER COLUMN seed_url DROP NOT NULL`. This edits
  catalog metadata only — no row rewrite, no data loss, existing values intact.
- Down: `UPDATE accession SET seed_url = '' WHERE seed_url IS NULL`, then
  `ALTER COLUMN seed_url SET NOT NULL` so rollback cannot fail on rows created
  under the new rule.
- The `accessions_with_metadata` view needs no change: it passes the column
  through and its column list is unchanged.

### 5. Entities hand-updated

Per project direction, do not run codegen. Change `seed_url` to
`Option<String>` in both `entity/src/accession.rs` and
`entity/src/accessions_with_metadata.rs`; the repo struct, `write_one_raw`
(passes `payload.original_url` straight through), response model, mocks, and
fixtures follow mechanically. The crawl path sets `Some(url)`.

### 6. Response contract

`AccessionsWithMetadataResponse.seed_url` becomes `Option<String>`, serializing
as `null`. This is a breaking API change; no compatibility shim is required.
The utoipa schema follows the type automatically.

## Risks / Trade-offs

- **Frontend renders a source URL today** → it must handle `null`; no
  compatibility requirement was requested, so coordinate at release time.
- **Down migration on a database with NULL rows** → the backfill to `''` runs
  before `SET NOT NULL`, so rollback always succeeds.
- **Rule only fires if callers invoke `.validate()`** → both current entry
  points do (route validates before the service); future consumers must call it,
  which is the documented contract of the model.
- **`url_filter` silently excludes URL-less accessions** → intended: filtering
  by URL should not return records with no URL.
- **Raw endpoint still accepts WACZ** → those requests require `original_url`;
  if raw WACZ support is removed later, the conditional rule can be deleted.

## Migration Plan

1. Deploy the migration first: `cd migration && cargo run -- up` against the
   local compose database, verify `\d accession` shows `seed_url` nullable,
   insert a NULL row, then test `down` → `up` round-trip.
2. Deploy the application after the migration (the new code writes NULLs, which
   the old constraint would reject).
3. Rollback: run the migration `down` (backfills `''` then restores
   `NOT NULL`), then redeploy the previous application version.
