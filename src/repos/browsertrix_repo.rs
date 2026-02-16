//! Repository module for interacting with the Browsertrix crawling service.
//!
//! This module provides functionality for authenticating with Browsertrix,
//! creating and managing web crawls, and retrieving WACZ (Web Archive Collection Zipped)
//! files from completed crawl operations.

use crate::config::BrowsertrixCrawlConfig;
use crate::models::request::CreateCrawlRequest;
use crate::models::response::{
    AuthResponse, CreateCrawlResponse, GetCrawlResponse, GetWaczUrlResponse,
};
use async_trait::async_trait;
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};
use uuid::Uuid;

/// Error type for Browsertrix API operations.
#[derive(Debug)]
pub enum BrowsertrixError {
    /// HTTP error response from Browsertrix API with status code and message.
    ApiError { status: u16, message: String },
    /// Network or request-level error.
    RequestError(String),
}

impl fmt::Display for BrowsertrixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BrowsertrixError::ApiError { status, message } => {
                write!(f, "Browsertrix API error ({}): {}", status, message)
            }
            BrowsertrixError::RequestError(msg) => {
                write!(f, "Browsertrix request error: {}", msg)
            }
        }
    }
}

impl std::error::Error for BrowsertrixError {}

/// Extracts a short error summary from Browsertrix error response body.
/// Returns first 200 characters of the response body.
async fn extract_error_summary(response: Response) -> String {
    let status = response.status();
    match response.text().await {
        Ok(body) => {
            // Truncate to first 200 chars to keep logs readable
            let truncated: String = body.chars().take(200).collect();
            if truncated.len() < body.len() {
                format!("{}...", truncated)
            } else {
                truncated
            }
        }
        Err(_) => format!("HTTP {}", status),
    }
}

/// HTTP-based implementation of the BrowsertrixRepo trait.
///
/// Provides methods for authenticating with and interacting with the Browsertrix
/// web crawling service through its REST API.
#[derive(Debug, Clone, Default)]
pub struct HTTPBrowsertrixRepo {
    pub username: String,
    pub password: String,
    pub org_id: Uuid,
    pub base_url: String,
    pub client: Client,
    pub login_url: String,
    pub create_crawl_url: String,
    pub access_token: Arc<RwLock<String>>,
}

/// Defines the interface for interacting with the Browsertrix web crawling service.
///
/// This trait provides methods for creating crawls, checking their status,
/// and retrieving archived content from completed crawls.
#[async_trait]
pub trait BrowsertrixRepo: Send + Sync {
    /// Retrieves the organization ID for Browsertrix operations.
    fn get_org_id(&self) -> Uuid;

    /// Refreshes the authentication token used for Browsertrix API calls.
    async fn refresh_auth(&self);

    /// Retrieves the URL for a WACZ file from a completed crawl.
    ///
    /// # Arguments
    /// * `job_run_id` - The ID of the completed crawl job
    async fn get_wacz_url(&self, job_run_id: &str) -> Result<String, BrowsertrixError>;

    /// Makes an authenticated request to the Browsertrix API.
    ///
    /// Handles re-authentication if the current token has expired.
    ///
    /// # Arguments
    /// * `req` - The request builder with the prepared request
    async fn make_request(&self, req: RequestBuilder) -> Result<Response, BrowsertrixError>;

    /// Authenticates with the Browsertrix API and returns an access token.
    async fn authenticate(&self) -> Result<String, BrowsertrixError>;

    /// Initializes the repository by obtaining and storing an access token.
    async fn initialize(&mut self);

    /// Creates a new web crawl in Browsertrix.
    ///
    /// # Arguments
    /// * `create_crawl_request` - The request containing crawl details
    async fn create_crawl(
        &self,
        create_crawl_request: CreateCrawlRequest,
    ) -> Result<CreateCrawlResponse, BrowsertrixError>;

    /// Retrieves the status of a crawl operation.
    ///
    /// # Arguments
    /// * `crawl_id` - The ID of the crawl to check
    async fn get_crawl_status(&self, crawl_id: Uuid) -> Result<String, BrowsertrixError>;

    /// Downloads the WACZ file from a completed crawl as a response for streaming.
    ///
    /// # Arguments
    /// * `crawl_id` - The ID of the completed crawl
    async fn download_wacz_stream(&self, crawl_id: &str) -> Result<Response, BrowsertrixError>;
}

#[async_trait]
impl BrowsertrixRepo for HTTPBrowsertrixRepo {
    fn get_org_id(&self) -> Uuid {
        self.org_id
    }

    async fn refresh_auth(&self) {
        let new_access_token = self
            .authenticate()
            .await
            .expect("Error logging into Browsertrix");
        let mut access_token = self.access_token.write().await;
        *access_token = new_access_token.clone();
    }
    async fn get_wacz_url(&self, job_run_id: &str) -> Result<String, BrowsertrixError> {
        let get_wacz_url = format!(
            "{}/orgs/{}/crawls/{job_run_id}/replay.json",
            self.base_url, self.org_id
        );
        let req = self.client.get(get_wacz_url.clone());
        let response = self.make_request(req).await?;

        let status = response.status();
        if !status.is_success() {
            let message = extract_error_summary(response).await;
            return Err(BrowsertrixError::ApiError {
                status: status.as_u16(),
                message,
            });
        }

        let wacz_response: GetWaczUrlResponse = response.json().await.map_err(|e| {
            BrowsertrixError::RequestError(format!("Failed to parse WACZ URL response: {}", e))
        })?;

        // Extract the first WACZ file URL from the response
        // Resources are WACZ files produced by a completed Browsertrix crawl.
        // A crawl can produce multiple WACZ files, but most crawls produce just one.
        // We take the first one as it's the main archive.
        let wacz_url = wacz_response
            .resources
            .first()
            .map(|r| r.path.clone())
            .ok_or_else(|| {
                error!("No WACZ resources found in Browsertrix response");
                BrowsertrixError::ApiError {
                    status: 200,
                    message: "No WACZ resources found in Browsertrix response".to_string(),
                }
            })?;

        Ok(wacz_url)
    }

    async fn make_request(&self, req: RequestBuilder) -> Result<Response, BrowsertrixError> {
        let original_req = req
            .try_clone()
            .expect("Requests should not be made with streams fool");
        let mut resp = original_req
            .bearer_auth(self.access_token.read().await)
            .send()
            .await
            .map_err(|e| BrowsertrixError::RequestError(format!("Request failed: {}", e)))?;

        if resp.status() == StatusCode::UNAUTHORIZED {
            info!("Got 401 HTTP code, reauthenticating...");
            self.refresh_auth().await;
            let req_with_refreshed_auth = req.bearer_auth(self.access_token.read().await);
            resp = req_with_refreshed_auth.send().await.map_err(|e| {
                BrowsertrixError::RequestError(format!("Request failed after reauth: {}", e))
            })?;
        }
        Ok(resp)
    }
    async fn authenticate(&self) -> Result<String, BrowsertrixError> {
        let mut params = HashMap::new();
        params.insert("username", self.username.clone());
        params.insert("password", self.password.clone());
        let response = self
            .client
            .post(self.login_url.clone())
            .form(&params)
            .send()
            .await
            .map_err(|e| {
                BrowsertrixError::RequestError(format!("Authentication request failed: {}", e))
            })?;

        let status = response.status();
        if !status.is_success() {
            let message = extract_error_summary(response).await;
            return Err(BrowsertrixError::ApiError {
                status: status.as_u16(),
                message,
            });
        }

        let auth_response: AuthResponse = response.json().await.map_err(|e| {
            BrowsertrixError::RequestError(format!("Failed to parse auth response: {}", e))
        })?;

        Ok(auth_response.access_token)
    }

    async fn initialize(&mut self) {
        let new_access_token = self
            .authenticate()
            .await
            .expect("Error logging into Browsertrix");
        let mut access_token = self.access_token.write().await;
        *access_token = new_access_token;
    }

    async fn create_crawl(
        &self,
        create_crawl_request: CreateCrawlRequest,
    ) -> Result<CreateCrawlResponse, BrowsertrixError> {
        let json_payload = BrowsertrixCrawlConfig::new(
            create_crawl_request.url,
            create_crawl_request.browser_profile,
        );
        let create_crawl_req = self
            .client
            .post(self.create_crawl_url.clone())
            .json(&json_payload);
        let response = self.make_request(create_crawl_req).await?;

        let status = response.status();
        if !status.is_success() {
            let message = extract_error_summary(response).await;
            return Err(BrowsertrixError::ApiError {
                status: status.as_u16(),
                message,
            });
        }

        let crawl_response: CreateCrawlResponse = response.json().await.map_err(|e| {
            BrowsertrixError::RequestError(format!(
                "Failed to parse crawl creation response: {}",
                e
            ))
        })?;

        Ok(crawl_response)
    }

    async fn get_crawl_status(&self, crawl_id: Uuid) -> Result<String, BrowsertrixError> {
        let get_crawl_status_url = format!(
            "{}/orgs/{}/crawlconfigs/{crawl_id}",
            self.base_url, self.org_id
        );
        let get_crawl_req = self.client.get(get_crawl_status_url.clone());
        let response = self.make_request(get_crawl_req).await?;

        let status = response.status();
        if !status.is_success() {
            let message = extract_error_summary(response).await;
            return Err(BrowsertrixError::ApiError {
                status: status.as_u16(),
                message,
            });
        }

        let crawl_response: GetCrawlResponse = response.json().await.map_err(|e| {
            BrowsertrixError::RequestError(format!("Failed to parse crawl status response: {}", e))
        })?;

        Ok(crawl_response.last_crawl_state)
    }

    async fn download_wacz_stream(&self, crawl_id: &str) -> Result<Response, BrowsertrixError> {
        let download_url = format!(
            "{}/orgs/{}/crawls/{crawl_id}/download?prefer_single_wacz=true",
            self.base_url, self.org_id
        );
        let req = self.client.get(download_url.clone());
        let response = self.make_request(req).await?;

        let status = response.status();
        if !status.is_success() {
            let message = extract_error_summary(response).await;
            return Err(BrowsertrixError::ApiError {
                status: status.as_u16(),
                message,
            });
        }

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_error_summary_truncates_long_body() {
        let long_body = "a".repeat(500);
        let result = extract_error_summary_body(&long_body);
        assert_eq!(result.len(), 203); // 200 chars + "..."
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_extract_error_summary_no_truncation_for_short_body() {
        let short_body = "Short error message";
        let result = extract_error_summary_body(short_body);
        assert_eq!(result, short_body);
        assert!(!result.ends_with("..."));
    }

    fn extract_error_summary_body(body: &str) -> String {
        let truncated: String = body.chars().take(200).collect();
        if truncated.len() < body.len() {
            format!("{}...", truncated)
        } else {
            truncated
        }
    }
}
