# Spec Delta

## Purpose

Defines how accessions are created from web crawls and raw file uploads, including which metadata formats require a source URL.

## ADDED Requirements

### Requirement: Raw uploads accept an optional source URL
The system SHALL accept raw file accession requests without `original_url` for every non-WACZ metadata format (currently `pdf` and `mp4`).

#### Scenario: PDF uploaded without a source URL
- **WHEN** a contributor posts a raw accession with `metadata_format` of `pdf` and no `original_url`
- **THEN** the system creates the accession and responds with 201 and a presigned upload URL
- **AND** the accession's `seed_url` is null

#### Scenario: PDF uploaded with a source URL
- **WHEN** a contributor posts a raw accession with `metadata_format` of `pdf` and a valid `original_url`
- **THEN** the system creates the accession and stores `original_url` as the accession's `seed_url`

#### Scenario: mp4 uploaded without a source URL
- **WHEN** a contributor posts a raw accession with `metadata_format` of `mp4` and no `original_url`
- **THEN** the system creates the accession with a null `seed_url`

### Requirement: WACZ accessions require a source URL
The system MUST reject raw accession requests whose `metadata_format` is `wacz` when `original_url` is absent.

#### Scenario: WACZ raw upload without a source URL
- **WHEN** a contributor posts a raw accession with `metadata_format` of `wacz` and no `original_url`
- **THEN** the system rejects the request with 400 Bad Request
- **AND** no accession is created

#### Scenario: WACZ raw upload with a source URL
- **WHEN** a contributor posts a raw accession with `metadata_format` of `wacz` and a valid `original_url`
- **THEN** the system creates the accession with that URL as `seed_url`

### Requirement: A supplied source URL must be a valid URL
The system SHALL validate `original_url` as a URL whenever it is present, regardless of metadata format.

#### Scenario: Malformed source URL
- **WHEN** a contributor posts a raw accession with an `original_url` that is not a valid URL
- **THEN** the system rejects the request with 400 Bad Request

### Requirement: Accessions without a source URL serialize as null
The system SHALL represent the absence of a source URL as JSON `null` in accession responses.

#### Scenario: Response for a URL-less accession
- **WHEN** a client retrieves an accession that has no source URL
- **THEN** the response includes `"seed_url": null`

#### Scenario: URL filtering excludes URL-less accessions
- **WHEN** a client lists accessions with a `url_filter`
- **THEN** accessions without a source URL are not included in the results

### Requirement: Crawl accessions always have a source URL
The system SHALL require a URL for crawl-based accession requests and SHALL store the resulting accession as WACZ with that URL as `seed_url`.

#### Scenario: Crawl request requires a URL
- **WHEN** a contributor posts a crawl accession without a valid `url`
- **THEN** the system rejects the request with 400 Bad Request

#### Scenario: Completed crawl stores the seed URL
- **WHEN** a crawl completes and the accession is written
- **THEN** the accession's metadata format is `wacz`
- **AND** its `seed_url` is the crawl URL
