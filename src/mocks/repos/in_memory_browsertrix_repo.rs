use crate::models::request::CreateCrawlRequest;
use crate::models::response::CreateCrawlResponse;
use crate::repos::browsertrix_repo::{BrowsertrixError, BrowsertrixRepo};
use async_trait::async_trait;
use reqwest::{RequestBuilder, Response};
use uuid::Uuid;

pub struct InMemoryBrowsertrixRepo {}

impl InMemoryBrowsertrixRepo {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl BrowsertrixRepo for InMemoryBrowsertrixRepo {
    fn get_org_id(&self) -> Uuid {
        Uuid::new_v4()
    }

    async fn refresh_auth(&self) {}

    async fn get_wacz_url(&self, _job_run_id: &str) -> Result<String, BrowsertrixError> {
        Ok("my url".to_owned())
    }

    async fn download_wacz_stream(&self, _crawl_id: &str) -> Result<Response, BrowsertrixError> {
        Ok(Response::from(http::Response::new("{}")))
    }

    async fn make_request(&self, _req: RequestBuilder) -> Result<Response, BrowsertrixError> {
        Ok(reqwest::Response::from(http::Response::new(
            "mock test data",
        )))
    }

    async fn authenticate(&self) -> Result<String, BrowsertrixError> {
        Ok("test_token".to_string())
    }

    async fn initialize(&mut self) {}

    async fn create_crawl(
        &self,
        _create_crawl_request: CreateCrawlRequest,
    ) -> Result<CreateCrawlResponse, BrowsertrixError> {
        Ok(CreateCrawlResponse {
            id: Uuid::new_v4(),
            run_now_job: "test_job_123".to_string(),
        })
    }

    async fn get_crawl_status(&self, _crawl_id: Uuid) -> Result<String, BrowsertrixError> {
        Ok("complete".to_owned())
    }
}
