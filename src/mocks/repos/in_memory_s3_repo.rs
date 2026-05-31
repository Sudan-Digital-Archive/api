use crate::repos::s3_repo::S3Repo;
use async_trait::async_trait;
use bytes::Bytes;
use std::error::Error as StdError;

#[derive(Debug, Clone, Default)]
pub struct InMemoryS3Repo {}

impl InMemoryS3Repo {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl S3Repo for InMemoryS3Repo {
    async fn new(
        bucket: String,
        _endpoint_url: &str,
        _access_key: &str,
        _secret_key: &str,
        _operation_timeout: u64,
        _operation_attempt_timeout: u64,
        _connect_timeout: u64,
    ) -> Result<Self, Box<dyn StdError>> {
        let _ = bucket;
        Ok(Self {})
    }

    async fn upload_from_bytes(
        &self,
        key: &str,
        _bytes: Bytes,
        _content_type: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        Ok(format!("mock-etag-{}", key))
    }

    async fn get_presigned_url(
        &self,
        _object_key: &str,
        _expires_in: u64,
    ) -> Result<String, Box<dyn StdError>> {
        Ok("my url".to_string())
    }

    async fn generate_presigned_put_url(
        &self,
        _object_key: &str,
        _expires_in: u64,
    ) -> Result<String, Box<dyn StdError>> {
        Ok("https://test-bucket.s3.example.com/mock-presigned-put-url".to_string())
    }

    async fn initiate_multipart_upload(
        &self,
        key: &str,
        _content_type: &str,
    ) -> Result<String, Box<dyn StdError>> {
        Ok(format!("mock-upload-id-{}", key))
    }

    async fn upload_part(
        &self,
        _key: &str,
        _upload_id: &str,
        part_number: i32,
        _bytes: Bytes,
    ) -> Result<(String, i32), Box<dyn StdError>> {
        Ok((format!("mock-etag-part-{}", part_number), part_number))
    }

    async fn complete_multipart_upload(
        &self,
        key: &str,
        _upload_id: &str,
        _parts: Vec<(String, i32)>,
    ) -> Result<String, Box<dyn StdError>> {
        Ok(format!("mock-final-etag-{}", key))
    }

    async fn delete_object(&self, _key: &str) -> Result<(), Box<dyn StdError>> {
        Ok(())
    }
}
