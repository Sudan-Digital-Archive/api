//! Configuration module for Browsertrix web archiving integration and application settings.
//! Handles environment variables and configuration structures for the archiving service.

use crate::models::common::BrowserProfile;
use http::HeaderValue;
use serde::Serialize;
use std::env;
use uuid::Uuid;

/// Configuration for Browsertrix web archiving service
#[derive(Debug, Clone, Default)]
pub struct BrowsertrixConfig {
    pub username: String,
    pub password: String,
    pub org_id: Uuid,
    pub base_url: String,
    pub login_url: String,
    pub create_crawl_url: String,
}

/// Global application configuration
#[derive(Debug, Clone, Default)]
pub struct AppConfig {
    pub archive_sender_email: String,
    pub browsertrix: BrowsertrixConfig,
    pub cors_urls: Vec<HeaderValue>,
    pub postgres_url: String,
    pub listener_address: String,
    pub jwt_expiry_hours: i64,
    pub jwt_cookie_domain: String,
    pub postmark_api_base: String,
    pub postmark_api_key: String,
    pub digital_ocean_spaces_endpoint_url: String,
    pub digital_ocean_spaces_bucket: String,
    pub digital_ocean_spaces_access_key: String,
    pub digital_ocean_spaces_secret_key: String,
    pub presigned_put_url_expiry_seconds: u64,
    pub presigned_get_url_expiry_seconds: u64,
    pub s3_operation_timeout: u64,
    pub s3_operation_attempt_timeout: u64,
    pub s3_connect_timeout: u64,
    pub api_prefix: String,
    /// Disable SQL query logging from sea-orm/sqlx (verbose, defaults to true)
    pub disable_sql_logging: bool,
    /// Use in-memory mock for Browsertrix
    pub mock_browsertrix: bool,
    /// Use in-memory mock for S3
    pub mock_s3: bool,
    /// Use in-memory mock for Postmark
    pub mock_postmark: bool,
    /// Use in-memory mock for Auth
    pub mock_auth: bool,
    /// Use in-memory mock for database repos
    pub mock_db: bool,
    /// Enable rate limiting (defaults to true)
    pub enable_rate_limiting: bool,
    /// Enable tracing/logging (defaults to true)
    pub enable_tracing: bool,
}

/// Builds application configuration from environment variables
pub fn build_app_config() -> AppConfig {
    let mock_db = env::var("MOCK_DB").unwrap_or_default() == "true";
    let postgres_url = if mock_db {
        env::var("POSTGRES_URL")
            .unwrap_or_else(|_| "postgres://mock:mock@localhost/mock".to_string())
    } else {
        env::var("POSTGRES_URL").expect("Missing POSTGRES_URL env var")
    };
    let archive_sender_email =
        env::var("ARCHIVE_SENDER_EMAIL").unwrap_or_else(|_| "test@example.com".to_string());
    let postmark_api_base =
        env::var("POSTMARK_API_BASE").unwrap_or_else(|_| "https://api.postmark.com".to_string());
    let postmark_api_key =
        env::var("POSTMARK_API_KEY").unwrap_or_else(|_| "mock_postmark_key".to_string());
    let username = env::var("BROWSERTRIX_USERNAME").unwrap_or_else(|_| "mock_user".to_string());
    let password = env::var("BROWSERTRIX_PASSWORD").unwrap_or_else(|_| "mock_password".to_string());
    let org_id = env::var("BROWSERTRIX_ORGID").unwrap_or_else(|_| Uuid::new_v4().to_string());
    let org_uuid = Uuid::parse_str(&org_id).expect("Could not parse browsertrix org id to uuid");
    let base_url = env::var("BROWSERTRIX_BROWSERTRIX_URL")
        .unwrap_or_else(|_| "https://mock-browsertrix.example.com".to_string());
    let login_url = format!("{base_url}/auth/jwt/login");
    let create_crawl_url = format!("{base_url}/orgs/{org_uuid}/crawlconfigs/");
    let browsertrix = BrowsertrixConfig {
        username,
        password,
        org_id: org_uuid,
        base_url,
        login_url,
        create_crawl_url,
    };
    let jwt_cookie_domain =
        env::var("JWT_COOKIE_DOMAIN").unwrap_or_else(|_| "localhost".to_string());
    let cors_urls_env_var =
        env::var("CORS_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let cors_urls = cors_urls_env_var
        .split(",")
        .map(|s| {
            HeaderValue::from_str(s)
                .expect("CORS_URL env var should contain comma separated origins")
        })
        .collect();
    let listener_address =
        env::var("LISTENER_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let jwt_expiry_hours = env::var("JWT_EXPIRY_HOURS")
        .unwrap_or_else(|_| "24".to_string())
        .parse()
        .expect("JWT_EXPIRY_HOURS should be a number");
    let digital_ocean_spaces_endpoint_url = env::var("DO_SPACES_ENDPOINT_URL")
        .unwrap_or_else(|_| "https://nyc3.digitaloceanspaces.com".to_string());
    let digital_ocean_spaces_bucket =
        env::var("DO_SPACES_BUCKET").unwrap_or_else(|_| "mock-bucket".to_string());
    let digital_ocean_spaces_access_key =
        env::var("DO_SPACES_ACCESS_KEY").unwrap_or_else(|_| "mock_access_key".to_string());
    let digital_ocean_spaces_secret_key =
        env::var("DO_SPACES_SECRET_KEY").unwrap_or_else(|_| "mock_secret_key".to_string());
    let presigned_put_url_expiry_seconds = env::var("PRESIGNED_PUT_URL_EXPIRY_SECONDS")
        .unwrap_or_else(|_| "3600".to_string())
        .parse()
        .expect("PRESIGNED_PUT_URL_EXPIRY_SECONDS should be a number");
    let presigned_get_url_expiry_seconds = env::var("PRESIGNED_GET_URL_EXPIRY_SECONDS")
        .unwrap_or_else(|_| "3600".to_string())
        .parse()
        .expect("PRESIGNED_GET_URL_EXPIRY_SECONDS should be a number");
    let s3_operation_timeout = env::var("S3_OPERATION_TIMEOUT")
        .unwrap_or("30".to_string())
        .parse()
        .expect("S3_OPERATION_TIMEOUT should be a number");
    let s3_operation_attempt_timeout = env::var("S3_OPERATION_ATTEMPT_TIMEOUT")
        .unwrap_or("10".to_string())
        .parse()
        .expect("S3_OPERATION_ATTEMPT_TIMEOUT should be a number");
    let s3_connect_timeout = env::var("S3_CONNECT_TIMEOUT")
        .unwrap_or("3".to_string())
        .parse()
        .expect("S3_CONNECT_TIMEOUT should be a number");
    let api_prefix = env::var("API_PREFIX").unwrap_or("".to_string());
    let disable_sql_logging = env::var("DISABLE_SQL_LOGGING")
        .unwrap_or("true".to_string())
        .parse()
        .expect("DISABLE_SQL_LOGGING should be true or false");
    let mock_browsertrix = env::var("MOCK_BROWSERTRIX").unwrap_or_default() == "true";
    let mock_s3 = env::var("MOCK_S3").unwrap_or_default() == "true";
    let mock_postmark = env::var("MOCK_POSTMARK").unwrap_or_default() == "true";
    let mock_auth = env::var("MOCK_AUTH").unwrap_or_default() == "true";
    let mock_db = env::var("MOCK_DB").unwrap_or_default() == "true";
    let enable_rate_limiting = env::var("ENABLE_RATE_LIMITING")
        .unwrap_or("true".to_string())
        .parse()
        .expect("ENABLE_RATE_LIMITING should be true or false");
    let enable_tracing = env::var("ENABLE_TRACING")
        .unwrap_or("true".to_string())
        .parse()
        .expect("ENABLE_TRACING should be true or false");
    AppConfig {
        archive_sender_email,
        browsertrix,
        cors_urls,
        postgres_url,
        listener_address,
        jwt_expiry_hours,
        jwt_cookie_domain,
        postmark_api_base,
        postmark_api_key,
        digital_ocean_spaces_endpoint_url,
        digital_ocean_spaces_bucket,
        digital_ocean_spaces_access_key,
        digital_ocean_spaces_secret_key,
        presigned_put_url_expiry_seconds,
        presigned_get_url_expiry_seconds,
        s3_operation_timeout,
        s3_operation_attempt_timeout,
        s3_connect_timeout,
        api_prefix,
        disable_sql_logging,
        mock_browsertrix,
        mock_s3,
        mock_postmark,
        mock_auth,
        mock_db,
        enable_rate_limiting,
        enable_tracing,
    }
}

/// Single URL seed configuration for Browsertrix crawl
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OneSeed {
    url: String,
    scope_type: String,
}

/// Configuration for URL crawling behavior and scope
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SeedsConfig {
    seeds: Vec<OneSeed>,
    scope_type: String,
    extra_hops: i32,
    use_sitemap: bool,
    fail_on_failed_seed: bool,
    behavior_timeout: Option<i32>,
    page_load_timeout: Option<i32>,
    page_extra_delay: Option<i32>,
    post_load_delay: i32,
    user_agent: Option<String>,
    limit: Option<i32>,
    lang: String,
    exclude: Vec<String>,
    behaviors: String,
}

/// Complete crawl configuration for Browsertrix service
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowsertrixCrawlConfig {
    job_type: String,
    name: String,
    description: Option<String>,
    scale: i8,
    profileid: String,
    run_now: bool,
    schedule: String,
    crawl_timeout: i32,
    max_crawl_size: i32,
    tags: Vec<String>,
    auto_add_collections: Vec<String>,
    config: SeedsConfig,
    crawler_channel: String,
    proxy_id: Option<String>,
}

impl BrowsertrixCrawlConfig {
    /// Creates a new crawl configuration for a single URL with default settings
    pub fn new(url: String, browser_profile: Option<BrowserProfile>) -> Self {
        let one_seed = OneSeed {
            url,
            scope_type: "page".to_string(),
        };
        let seeds_config = SeedsConfig {
            seeds: vec![one_seed],
            scope_type: "page".to_string(),
            extra_hops: 0,
            use_sitemap: false,
            fail_on_failed_seed: false,
            behavior_timeout: None,
            page_load_timeout: None,
            page_extra_delay: None,
            post_load_delay: 120,
            user_agent: None,
            limit: None,
            lang: "en".to_string(),
            exclude: vec![],
            behaviors: "autoscroll,autoplay,autofetch,siteSpecific".to_string(),
        };
        let mut profileid = "".to_string();
        if let Some(browser_profile_name) = browser_profile {
            // profile ids here are from Browsertrix API
            // to get them you need to do list profiles
            profileid = match browser_profile_name {
                BrowserProfile::Facebook => "b1cd3192-a554-41e1-9509-0cbff3b3df16".to_string(),
            };
        }
        BrowsertrixCrawlConfig {
            job_type: "custom".to_string(),
            name: "".to_string(),
            description: None,
            scale: 1,
            profileid,
            run_now: true,
            schedule: "".to_string(),
            crawl_timeout: 0,
            max_crawl_size: 1000000000,
            tags: vec![],
            auto_add_collections: vec![],
            config: seeds_config,
            crawler_channel: "default".to_string(),
            proxy_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crawl_config_new_different_urls() {
        let config1 = BrowsertrixCrawlConfig::new("https://example.com".to_string(), None);
        let config2 = BrowsertrixCrawlConfig::new(
            "https://different.com".to_string(),
            Some(BrowserProfile::Facebook),
        );

        assert_eq!(config1.config.seeds[0].url, "https://example.com");
        assert_eq!(config2.config.seeds[0].url, "https://different.com");
        assert_ne!(config1.config.seeds[0].url, config2.config.seeds[0].url);
    }
}
