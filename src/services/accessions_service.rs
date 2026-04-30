//! Service layer for managing archival accessions (records).
//!
//! This module handles the business logic for creating, retrieving, and listing
//! archival records, including their associated web crawls and metadata in both
//! Arabic and English.
use crate::models::common::MetadataLanguage;
use crate::models::request::AccessionPaginationWithPrivate;
use crate::models::request::{
    CreateAccessionRequest, CreateAccessionRequestRaw, CreateCrawlRequest, UpdateAccessionRequest,
};
use crate::models::response::{
    GetOneAccessionResponse, InitiateUploadResponse, ListAccessionsResponse,
};
use crate::repos::accessions_repo::AccessionsRepo;
use crate::repos::auth_repo::AuthRepo;
use crate::repos::browsertrix_repo::BrowsertrixRepo;
use crate::repos::emails_repo::EmailsRepo;
use crate::repos::s3_repo::S3Repo;
use crate::services::contributors_service::ContributorsService;
use crate::services::creators_service::CreatorsService;
use crate::services::locations_service::LocationsService;
use crate::services::subjects_service::SubjectsService;
use ::entity::accessions_with_metadata::Model as AccessionWithMetadataModel;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use bytes::Bytes;
use entity::sea_orm_active_enums::{CrawlStatus, DublinMetadataFormat};
use futures::StreamExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use validator::Validate;

// Using this as the min part size for multipart uploads to S3. This is low since this code is designed to run in
// a very low memory container environment. Plus we don't want to allow too large uploads anyway, so we are mostly
// using this to support streaming uploads of files that are slightly over 5MB, which will be the majority of uploads
// to the archive
static FIVE_MB: usize = 5 * 1024 * 1024;

pub(crate) struct MetadataValidationParams {
    pub(crate) subjects: Vec<i32>,
    pub(crate) metadata_language: MetadataLanguage,
    pub(crate) metadata_location_id: Option<i32>,
    pub(crate) metadata_creator_id: Option<i32>,
    pub(crate) metadata_contributor_ids: Vec<i32>,
    pub(crate) metadata_contributor_role_ids: Vec<Option<i32>>,
}

/// Service for managing archival accessions and their associated web crawls.
/// Uses dynamic traits for dependency injection
#[derive(Clone)]
pub struct AccessionsService {
    pub accessions_repo: Arc<dyn AccessionsRepo>,
    pub auth_repo: Arc<dyn AuthRepo>,
    pub browsertrix_repo: Arc<dyn BrowsertrixRepo>,
    pub emails_repo: Arc<dyn EmailsRepo>,
    pub s3_repo: Arc<dyn S3Repo>,
    pub subjects_service: SubjectsService,
    pub locations_service: LocationsService,
    pub creators_service: CreatorsService,
    pub contributors_service: ContributorsService,
    pub presigned_put_url_expiry_seconds: u64,
}

impl AccessionsService {
    /// Lists paginated accessions with optional filtering.
    ///
    /// # Arguments
    /// * `params` - Struct containing all pagination and filtering parameters
    ///
    /// # Returns
    /// JSON response containing paginated accessions or an error response
    pub async fn list(self, params: AccessionPaginationWithPrivate) -> Response {
        info!(
            "Getting page {} of {} accessions with per page {}...",
            params.page, params.lang, params.per_page
        );

        let rows = self.accessions_repo.list_paginated(params.clone()).await;

        match rows {
            Err(err) => {
                error!(%err, "Error occurred paginating accessions");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
            Ok(rows) => {
                let resp = ListAccessionsResponse {
                    items: rows.0.into_iter().map(Into::into).collect(),

                    num_pages: rows.1,
                    page: params.page,
                    per_page: params.per_page,
                };
                Json(resp).into_response()
            }
        }
    }
    /// Retrieves a single accession by ID with its associated metadata and WACZ URL.
    ///
    /// # Arguments
    /// * `id` - The unique identifier of the accession
    ///
    /// # Returns
    /// JSON response containing the accession details or an error response
    pub async fn get_one(self, id: i32, private: bool) -> Response {
        info!("Getting {private} accession with id {id}");
        let query_result = self.accessions_repo.get_one(id, private).await;
        match query_result {
            Err(query_result) => {
                error!(%query_result, "Error occurred retrieving accession");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
            Ok(query_result) => {
                if let Some(accession) = query_result {
                    self.enrich_accession_with_wacz_url(accession).await
                } else {
                    (StatusCode::NOT_FOUND, "No such record").into_response()
                }
            }
        }
    }

    /// Enriches an accession with a WACZ URL.
    ///
    /// This method determines the source of the WACZ file:
    /// 1. If an `s3_filename` is present and the format is WACZ, the file is stored in our own
    ///    DigitalOcean Spaces storage. We generate a presigned URL for direct access.
    /// 2. If no `s3_filename` is present but a `job_run_id` exists, the file is still in Browsertrix.
    ///    We retrieve the replay URL from the Browsertrix service.
    /// 3. If neither is present return an error; this shouldn't happen
    async fn enrich_accession_with_wacz_url(
        self,
        accession: AccessionWithMetadataModel,
    ) -> Response {
        let accession_for_response = accession.clone();
        match (
            accession.s3_filename.as_deref(),
            &accession.dublin_metadata_format,
        ) {
            // If it has an s3 filename, then we know its in our own digital ocean spaces storage
            (Some(s3_filename), DublinMetadataFormat::Wacz) => {
                match self.s3_repo.get_presigned_url(s3_filename, 3600).await {
                    Ok(presigned_url) => {
                        let resp = GetOneAccessionResponse {
                            accession: accession_for_response.into(),
                            wacz_url: presigned_url,
                        };
                        Json(resp).into_response()
                    }
                    Err(err) => {
                        error!(%err, "Error occurred generating presigned url");
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Could not retrieving wacz url from s3 storage",
                        )
                            .into_response()
                    }
                }
            }
            _ => {
                if let Some(ref job_run_id) = accession.job_run_id {
                    match self.browsertrix_repo.get_wacz_url(job_run_id).await {
                        Ok(wacz_url) => {
                            let resp = GetOneAccessionResponse {
                                accession: accession_for_response.into(),
                                wacz_url,
                            };
                            Json(resp).into_response()
                        }
                        Err(err) => {
                            error!(%err, "Error occurred retrieving wacz url");
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "Error retrieving wacz url",
                            )
                                .into_response()
                        }
                    }
                } else {
                    error!(
                        "Error occurred generating wacz URL, no s3 filename or job run id present"
                    );
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Could not retrieving wacz url from s3 storage",
                    )
                        .into_response()
                }
            }
        }
    }
    /// Creates a new accession by initiating a web crawl and storing the metadata.
    ///
    /// This method performs the following steps:
    /// 1. Launches a web crawl for the specified URL
    /// 2. Polls the crawl status for up to 30 minutes
    /// 3. Creates an accession record once the crawl is complete
    ///
    /// You should validate that `metadata_subjects` exist in the
    /// payload before calling this method - it will error out
    /// if they don't.
    ///
    /// # Arguments
    /// * `payload` - The creation request containing URL and metadata
    /// * `user_id` - UUID of the user who requested the crawl
    pub async fn create_one(self, payload: CreateAccessionRequest, user_id: Uuid) {
        let create_crawl_request = CreateCrawlRequest {
            url: payload.url.clone(),
            browser_profile: payload.browser_profile.clone(),
        };
        let resp = self
            .browsertrix_repo
            .create_crawl(create_crawl_request)
            .await;
        match resp {
            Err(err) => {
                error!(%err, "Error occurred launching browsertrix crawl");
            }
            Ok(resp) => {
                info!("Launched crawl request for url {}", payload.url.clone());
                let time_to_sleep = Duration::from_secs(60);
                let time_to_sleep_as_secs = time_to_sleep.as_secs();
                let mut count = 0;
                while count <= 30 {
                    count += 1;
                    info!("Polled {count} time(s) for url {}", payload.url.clone());
                    let get_crawl_resp = self.browsertrix_repo.get_crawl_status(resp.id).await;
                    match get_crawl_resp {
                        Ok(valid_crawl_resp) => {
                            if valid_crawl_resp == "complete" {
                                let crawl_time_secs = (time_to_sleep * count).as_secs();
                                info!(%valid_crawl_resp, %count, "Crawl complete after {crawl_time_secs}s");
                                let trimmed_title = payload.metadata_title.trim().to_string();
                                let trimmed_description = payload
                                    .metadata_description
                                    .map(|description| description.trim().to_string());

                                let wacz_response = match self
                                    .browsertrix_repo
                                    .download_wacz_stream(&resp.run_now_job)
                                    .await
                                {
                                    Ok(response) => response,
                                    Err(err) => {
                                        error!(%err, "Error occurred downloading WACZ file, aborting accession creation");
                                        return;
                                    }
                                };

                                let unique_filename = format!("{}.wacz", Uuid::new_v4());
                                if let Err(err) = self
                                    .clone()
                                    .upload_from_stream(
                                        unique_filename.clone(),
                                        wacz_response.bytes_stream(),
                                        "application/wacz".to_string(),
                                    )
                                    .await
                                {
                                    error!("Error occurred uploading WACZ file to S3: {:?}, aborting accession creation", err);
                                    return;
                                };
                                
                                info!("WACZ file uploaded to S3 with filename {}", unique_filename);
                                let create_accessions_request = CreateAccessionRequest {
                                    url: payload.url.clone(),
                                    browser_profile: payload.browser_profile,
                                    metadata_language: payload.metadata_language,
                                    metadata_title: trimmed_title,
                                    metadata_description: trimmed_description,
                                    metadata_time: payload.metadata_time,
                                    metadata_subjects: payload.metadata_subjects,
                                    is_private: payload.is_private,
                                    metadata_format: DublinMetadataFormat::Wacz,
                                    s3_filename: Some(unique_filename.clone()),
                                    send_email_notification: payload.send_email_notification,
                                    metadata_location_id: payload.metadata_location_id,
                                    metadata_creator_id: payload.metadata_creator_id,
                                    metadata_contributor_ids: payload.metadata_contributor_ids,
                                    metadata_contributor_role_ids: payload
                                        .metadata_contributor_role_ids,
                                };
                                let write_result = self
                                    .accessions_repo
                                    .write_one(
                                        create_accessions_request,
                                        self.browsertrix_repo.get_org_id(),
                                        resp.id,
                                        resp.run_now_job,
                                        CrawlStatus::Complete,
                                    )
                                    .await;
                                match write_result {
                                    Err(err) => {
                                        error!(%err, "Error occurred writing crawl result to db!");
                                    }
                                    Ok(id) => {
                                        info!("Crawl result written to db successfully");
                                        if payload.send_email_notification {
                                            // Look up user email only when needed
                                            match self.auth_repo.get_user_by_id(user_id).await {
                                                Ok(Some(user)) => {
                                                    let email_subject = format!(
                                                        "Your URL {} has been archived!",
                                                        payload.url
                                                    );
                                                    let email_body = format!(
                                                        "We have archived your <a href='https://sudandigitalarchive.com/archive/{}?isPrivate={}&lang={}'>url</a>.",
                                                        id, payload.is_private, payload.metadata_language
                                                    );
                                                    let email_result = self
                                                        .emails_repo
                                                        .send_email(
                                                            user.email,
                                                            email_subject,
                                                            email_body,
                                                        )
                                                        .await;
                                                    info!(
                                                        "Email sent to user with id {id} for url {}",
                                                        payload.url
                                                    );
                                                    if let Err(err) = email_result {
                                                        error!(%err, "Error occurred sending email to user");
                                                    }
                                                }
                                                Ok(None) => {
                                                    error!("User with id {} not found, cannot send email notification", user_id);
                                                }
                                                Err(err) => {
                                                    error!(%err, "Error looking up user with id {} for email notification", user_id);
                                                }
                                            }
                                        } else {
                                            info!(
                                                "Email notification skipped for user with id {id} for url {} (send_email_notification=false)",
                                                payload.url
                                            );
                                        }
                                    }
                                }
                                break;
                            } else {
                                sleep(time_to_sleep).await;
                            }
                        }
                        Err(invalid_crawl_resp) => {
                            error!(%invalid_crawl_resp, "Invalid crawl response, trying again in {time_to_sleep_as_secs}s");
                            sleep(time_to_sleep).await;
                        }
                    }
                }
            }
        }
    }

    /// Deletes a single accession by ID.
    ///
    /// # Arguments
    /// * `id` - The unique identifier of the accession
    ///
    /// # Returns
    /// Response indicating success or failure of the deletion
    pub async fn delete_one(self, id: i32) -> Response {
        info!("Deleting accession with id {id}");
        let delete_result = self.accessions_repo.delete_one(id).await;
        match delete_result {
            Err(err) => {
                error!(%err, "Error occurred deleting accession");
                err.into_response()
            }
            Ok(delete_result) => {
                if let Some(accession) = delete_result {
                    if let Some(s3_filename) = accession.s3_filename {
                        if let Err(err) = self.s3_repo.delete_object(&s3_filename).await {
                            error!(%err, "Error deleting s3 object {s3_filename}");
                            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error")
                                .into_response();
                        } else {
                            info!("Deleted s3 object {s3_filename}");
                        }
                    }
                    (StatusCode::OK, "Accession deleted").into_response()
                } else {
                    (StatusCode::NOT_FOUND, "No such record").into_response()
                }
            }
        }
    }

    fn find_duplicate_contributor(ids: &[i32]) -> Option<i32> {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        ids.iter().find(|&&id| !seen.insert(id)).copied()
    }

    /// Updates a single accession by ID.
    ///
    /// # Arguments
    /// * `id` - The unique identifier of the accession
    /// * `payload` - The update request containing new metadata
    ///
    /// # Returns
    /// Response indicating success or failure of the update
    pub async fn update_one(self, id: i32, payload: UpdateAccessionRequest) -> Response {
        info!("Updating accession with id {id}");

        let contributor_ids = &payload.metadata_contributor_ids;

        if let Some(duplicate_id) = Self::find_duplicate_contributor(contributor_ids) {
            warn!(%duplicate_id, "Duplicate contributor ID in update request");
            return (
                StatusCode::BAD_REQUEST,
                format!(
                    "Contributor ID {} is specified multiple times. Each contributor can only have multiple roles, not be duplicated.",
                    duplicate_id
                ),
            )
                .into_response();
        }

        let is_private = payload.is_private;
        let update_result = self.accessions_repo.update_one(id, payload).await;
        match update_result {
            Err(err) => {
                error!(%err, "Error occurred updating accession");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
            Ok(Some(_)) => self.get_one(id, is_private).await,
            Ok(None) => (StatusCode::NOT_FOUND, "Accession not found").into_response(),
        }
    }

    /// Initiates a raw file upload by creating a placeholder in S3 and returning a presigned PUT URL.
    ///
    /// # Arguments
    /// * `payload` - The raw accession request with metadata (minus the file)
    ///
    /// # Returns
    /// JSON response containing accession ID and presigned upload URL
    pub async fn initiate_raw_upload(self, mut payload: CreateAccessionRequestRaw) -> Response {
        let file_ext = match payload.metadata_format {
            DublinMetadataFormat::Wacz => "wacz",
        };

        let unique_filename = format!("{}.{}", Uuid::new_v4(), file_ext);
        payload.s3_filename = unique_filename.clone();

        info!("Creating placeholder in S3: {}", unique_filename);

        let placeholder_content = Bytes::new();
        match self
            .s3_repo
            .upload_from_bytes(
                &unique_filename,
                placeholder_content,
                "application/octet-stream",
            )
            .await
        {
            Ok(_) => {
                info!("Placeholder created in S3: {}", unique_filename);
            }
            Err(err) => {
                error!(%err, "Failed to create placeholder in S3: {}", unique_filename);
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Failed to create S3 placeholder",
                )
                    .into_response();
            }
        }

        let upload_url = match self
            .s3_repo
            .generate_presigned_put_url(&unique_filename, self.presigned_put_url_expiry_seconds)
            .await
        {
            Ok(url) => {
                info!("Generated presigned PUT URL for: {}", unique_filename);
                url
            }
            Err(e) => {
                error!("Failed to generate presigned PUT URL: {}", e);
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Failed to generate upload URL",
                )
                    .into_response();
            }
        };

        let write_result = self.accessions_repo.write_one_raw(payload).await;
        match write_result {
            Err(err) => {
                error!(%err, "Error occurred writing raw accession to db");
                let _ = self.s3_repo.delete_object(&unique_filename).await;
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error").into_response()
            }
            Ok(id) => {
                info!("Raw accession written to db successfully with id {id}");
                let response = InitiateUploadResponse {
                    accession_id: id,
                    upload_url,
                };
                (StatusCode::CREATED, Json(response)).into_response()
            }
        }
    }

    pub async fn validate_metadata_references(
        self,
        params: MetadataValidationParams,
    ) -> Result<(), Response> {
        if !params.subjects.is_empty() {
            let subjects_exist = self
                .subjects_service
                .clone()
                .verify_subjects_exist(params.subjects, params.metadata_language)
                .await;
            match subjects_exist {
                Err(err) => {
                    return Err(
                        (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
                    );
                }
                Ok(flag) => {
                    if !flag {
                        return Err(
                            (StatusCode::BAD_REQUEST, "Subjects do not exist").into_response()
                        );
                    }
                }
            }
        }

        let mut location_ids: Vec<i32> = vec![];
        if let Some(id) = params.metadata_location_id {
            location_ids.push(id);
        }
        if !location_ids.is_empty() {
            let locations_exist = self
                .locations_service
                .clone()
                .verify_locations_exist(location_ids, params.metadata_language)
                .await;
            match locations_exist {
                Err(err) => {
                    return Err(
                        (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
                    );
                }
                Ok(flag) => {
                    if !flag {
                        return Err(
                            (StatusCode::BAD_REQUEST, "Locations do not exist").into_response()
                        );
                    }
                }
            }
        }

        let mut creator_ids: Vec<i32> = vec![];
        if let Some(id) = params.metadata_creator_id {
            creator_ids.push(id);
        }
        if !creator_ids.is_empty() {
            let creators_exist = self
                .creators_service
                .clone()
                .verify_creators_exist(creator_ids, params.metadata_language)
                .await;
            match creators_exist {
                Err(err) => {
                    return Err(
                        (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
                    );
                }
                Ok(flag) => {
                    if !flag {
                        return Err(
                            (StatusCode::BAD_REQUEST, "Creators do not exist").into_response()
                        );
                    }
                }
            }
        }

        if !params.metadata_contributor_ids.is_empty()
            && params.metadata_contributor_ids.len() != params.metadata_contributor_role_ids.len()
        {
            return Err((
                StatusCode::BAD_REQUEST,
                "Contributor IDs and role IDs must have the same length",
            )
                .into_response());
        }

        let contributor_ids: Vec<i32> = params.metadata_contributor_ids.clone();
        let role_ids: Vec<i32> = params
            .metadata_contributor_role_ids
            .iter()
            .flatten()
            .copied()
            .collect();

        if !contributor_ids.is_empty() {
            let contributors_exist = self
                .contributors_service
                .clone()
                .verify_contributors_exist(contributor_ids.clone(), params.metadata_language)
                .await;
            match contributors_exist {
                Err(err) => {
                    return Err(
                        (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
                    );
                }
                Ok(flag) => {
                    if !flag {
                        return Err(
                            (StatusCode::BAD_REQUEST, "Contributors do not exist").into_response()
                        );
                    }
                }
            }
        }

        if !role_ids.is_empty() {
            let roles_exist = self
                .contributors_service
                .clone()
                .verify_roles_exist(role_ids.clone(), params.metadata_language)
                .await;
            match roles_exist {
                Err(err) => {
                    return Err(
                        (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
                    );
                }
                Ok(flag) => {
                    if !flag {
                        return Err((StatusCode::BAD_REQUEST, "Contributor roles do not exist")
                            .into_response());
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn get_dublin_metadata_id(
        &self,
        accession_id: i32,
        metadata_language: MetadataLanguage,
    ) -> Result<Option<i32>, Response> {
        self.accessions_repo
            .get_dublin_metadata_id(accession_id, metadata_language)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())
    }

    /// Uploads from a generic stream to S3 with smart chunk handling.
    ///
    /// This method streams the bytes and decides on upload strategy as it reads:
    /// - Data under 5MB: buffered and uploaded with a single request
    /// - Data over 5MB: multipart upload initiated and chunks streamed directly to S3
    ///
    /// # Arguments
    /// * `key` - The S3 object key where the file will be uploaded
    /// * `stream` - The stream of byte chunks
    /// * `content_type` - The MIME type of the file
    ///
    /// # Returns
    /// Result containing the upload ID or an error response
    async fn upload_from_stream<S, E>(
        self,
        key: String,
        mut stream: S,
        content_type: String,
    ) -> Result<String, Response>
    where
        S: futures::Stream<Item = Result<Bytes, E>> + Unpin + Send,
        E: std::fmt::Display,
    {
        debug!(
            "Starting streaming upload for key: {} with content type: {}",
            key, content_type
        );

        let mut buffer = Vec::with_capacity(FIVE_MB);
        let mut total_size = 0;
        let mut upload_id: Option<String> = None;
        let mut upload_parts: Vec<(String, i32)> = Vec::new();
        let mut part_number = 1i32;

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.map_err(|err| {
                error!("Failed to read chunk from stream: {}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to read file stream",
                )
                    .into_response()
            })?;

            total_size += chunk.len();
            buffer.extend_from_slice(&chunk);
            debug!(
                "Received chunk of {} bytes, total so far: {:.1} MB",
                chunk.len(),
                total_size as f64 / 1024.0 / 1024.0
            );

            // case where we are under 5MB so we don't do multipart upload since this requires
            // 5MB otherwise it fails
            if upload_id.is_none() && total_size <= FIVE_MB {
                continue;

            // Case where we haven't started a multipart upload but we're over 5MB, so we need to start one!
            } else if upload_id.is_none() && total_size > FIVE_MB {
                debug!(
                    "File exceeded 5MB threshold at {:.1} MB, initiating multipart upload.",
                    total_size as f64 / 1024.0 / 1024.0
                );
                match self
                    .s3_repo
                    .initiate_multipart_upload(&key, &content_type)
                    .await
                {
                    Ok(id) => {
                        upload_id = Some(id.clone());
                        info!("Initiated multipart upload with id: {}", id);
                    }
                    Err(err) => {
                        error!(%err, "Failed to initiate multipart upload for key: {}", key);
                        return Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Failed to initiate upload",
                        )
                            .into_response());
                    }
                }
            }
            // Case where we have started a multipart upload already so we need to upload the next chunk!
            if let Some(ref id) = upload_id {
                if buffer.len() <= FIVE_MB {
                    debug!("Waiting for chunk to reach five mb, the min size for each part");
                    continue;
                }
                let part_bytes = Bytes::from(buffer.split_off(0));
                debug!(
                    "Uploading part {} with {:.1} MB.",
                    part_number,
                    part_bytes.len() as f64 / 1024.0 / 1024.0
                );
                match self
                    .s3_repo
                    .upload_part(&key, id, part_number, part_bytes)
                    .await
                {
                    Ok((etag, _)) => {
                        upload_parts.push((etag, part_number));
                        debug!("Successfully uploaded part {}", part_number);
                        part_number += 1;
                    }
                    Err(err) => {
                        error!(%err, "Failed to upload part {} for key: {}", part_number, key);
                        return Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Failed to upload file part",
                        )
                            .into_response());
                    }
                }
            } else {
                error!("Multipart upload hasn't started and size exceeded 5MB, which should not happen :-(");
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to broker stream into multipart or single upload",
                )
                    .into_response());
            }
        }
        debug!("Exited loop for reading stream for key: {}", key);
        // Handle stream end; we now either need to bundle up all the multipart upload parts into the final
        // object or if we didn't do a multipart upload because it was under 5MB, we need to do a single upload
        if let Some(id) = upload_id {
            if !buffer.is_empty() {
                debug!(
                    "Uploading final part {} with {:.1} MB",
                    part_number,
                    buffer.len() as f64 / 1024.0 / 1024.0
                );
                let part_bytes = Bytes::from(buffer.split_off(0));
                match self
                    .s3_repo
                    .upload_part(&key, &id, part_number, part_bytes)
                    .await
                {
                    Ok((etag, _)) => {
                        upload_parts.push((etag, part_number));
                        debug!("Successfully uploaded final part {}", part_number);
                    }
                    Err(err) => {
                        error!(%err, "Failed to upload final part for key: {}", key);
                        return Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Failed to upload final part",
                        )
                            .into_response());
                    }
                }
            }

            debug!(
                "Completing multipart upload for key: {} with  parts count: {}",
                key,
                upload_parts.len()
            );
            match self
                .s3_repo
                .complete_multipart_upload(&key, &id, upload_parts)
                .await
            {
                Ok(_) => {
                    info!(
                        "Successfully completed multipart upload for key: {}, total size: {:.1} MB",
                        key,
                        total_size as f64 / 1024.0 / 1024.0
                    );
                    Ok(id)
                }
                Err(err) => {
                    error!(%err, "Failed to complete multipart upload for key: {}", key);
                    Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to complete upload",
                    )
                        .into_response())
                }
            }
        } else {
            info!(
                "Using simple upload for {:.1} MB",
                total_size as f64 / 1024.0 / 1024.0
            );
            match self
                .s3_repo
                .upload_from_bytes(&key, Bytes::from(buffer), &content_type)
                .await
            {
                Ok(_) => {
                    info!(
                        "Successfully uploaded file with key: {} and content type: {}",
                        key, content_type
                    );
                    Ok(key)
                }
                Err(err) => {
                    error!(%err, "Failed to upload file to S3. Key: {}, Content-Type: {}", key, content_type);
                    Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to upload file")
                        .into_response())
                }
            }
        }
    }
}
