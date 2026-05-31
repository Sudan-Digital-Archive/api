//! Application factory module for configuring and building the API server.
//!
//! This module handles the setup of:
//! - Rate limiting (via tower-governor)
//! - CORS configuration
//! - Middleware stack (compression, timeout, tracing)
//! - Route registration
//! - Service/repository construction based on configuration
//!
//! # Rate Limiting
//! The application uses tower-governor for rate limiting with default configuration:
//! - 32 requests per minute per IP address
//! - Regular cleanup of rate limiting storage every 60 seconds
//!
//! Rate limiting can be disabled via ENABLE_RATE_LIMITING=false env var.

use crate::config::AppConfig;
use crate::mocks::repos::{
    InMemoryAccessionsRepo, InMemoryAuthRepo, InMemoryBrowsertrixRepo, InMemoryCollectionsRepo,
    InMemoryContributorRolesRepo, InMemoryContributorsRepo, InMemoryCreatorsRepo,
    InMemoryEmailsRepo, InMemoryLocationsRepo, InMemoryRelationsRepo, InMemoryS3Repo,
    InMemorySubjectsRepo,
};
use crate::open_api_spec::ApiDoc;
use crate::repos::accessions_repo::DBAccessionsRepo;
use crate::repos::auth_repo::DBAuthRepo;
use crate::repos::browsertrix_repo::{BrowsertrixRepo, HTTPBrowsertrixRepo};
use crate::repos::collections_repo::DBCollectionsRepo;
use crate::repos::contributor_roles_repo::DBContributorRolesRepo;
use crate::repos::contributors_repo::DBContributorsRepo;
use crate::repos::creators_repo::DBCreatorsRepo;
use crate::repos::emails_repo::{EmailsRepo, PostmarkEmailsRepo};
use crate::repos::locations_repo::DBLocationsRepo;
use crate::repos::relations_repo::DBRelationsRepo;
use crate::repos::s3_repo::{DigitalOceanSpacesRepo, S3Repo};
use crate::repos::subjects_repo::DBSubjectsRepo;
use crate::routes::accessions::get_accessions_routes;
use crate::routes::auth::get_auth_routes;
use crate::routes::collections::get_collections_routes;
use crate::routes::contributors::get_contributors_routes;
use crate::routes::creators::get_creators_routes;
use crate::routes::health::healthcheck;
use crate::routes::locations::get_locations_routes;
use crate::routes::relations::get_relations_routes;
use crate::routes::subjects::get_subjects_routes;
use crate::services::accessions_service::AccessionsService;
use crate::services::auth_service::AuthService;
use crate::services::collections_service::CollectionsService;
use crate::services::contributors_service::ContributorsService;
use crate::services::creators_service::CreatorsService;
use crate::services::locations_service::LocationsService;
use crate::services::relations_service::RelationsService;
use crate::services::subjects_service::SubjectsService;
use axum::extract::MatchedPath;
use axum::http::Request;
use axum::response::Redirect;
use axum::routing::get;
use axum::Router;
use http::header::CONTENT_TYPE;
use http::{Method, StatusCode};
use reqwest::Client;
use sea_orm::{ConnectOptions, Database};
use std::error::Error as StdError;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tower::ServiceBuilder;
use tower_governor::{governor::GovernorConfig, GovernorLayer};
use tower_http::cors::CorsLayer;
use tower_http::{compression::CompressionLayer, timeout::TimeoutLayer, trace::TraceLayer};
use tracing::info_span;
use tracing_subscriber::util::SubscriberInitExt;
use utoipa::OpenApi;
use utoipa_swagger_ui::{Config, SwaggerUi};
/// Application state shared across routes
#[derive(Clone)]
pub struct AppState {
    pub accessions_service: AccessionsService,
    pub auth_service: AuthService,
    pub collections_service: CollectionsService,
    pub subjects_service: SubjectsService,
    pub locations_service: LocationsService,
    pub creators_service: CreatorsService,
    pub contributors_service: ContributorsService,
    pub relations_service: RelationsService,
}

/// Builds the application with appropriate repositories based on configuration.
/// This function handles dependency injection for all services, choosing either
/// real database/external service implementations or in-memory mocks based on
/// the MOCK_* environment variables.
pub async fn build_app(app_config: &AppConfig) -> Result<(AppState, AppConfig), Box<dyn StdError>> {
    let need_db = !app_config.mock_db || !app_config.mock_auth || !app_config.mock_postmark;
    let db_session = if need_db {
        let mut opt = ConnectOptions::new(app_config.postgres_url.clone());
        opt.sqlx_logging(!app_config.disable_sql_logging);
        Some(Database::connect(opt).await?)
    } else {
        None
    };

    let accessions_repo: Arc<dyn crate::repos::accessions_repo::AccessionsRepo> =
        if app_config.mock_db {
            Arc::new(InMemoryAccessionsRepo::default())
        } else {
            Arc::new(DBAccessionsRepo {
                db_session: db_session.clone().unwrap(),
            })
        };

    let auth_repo: Arc<dyn crate::repos::auth_repo::AuthRepo> = if app_config.mock_auth {
        Arc::new(InMemoryAuthRepo::default())
    } else {
        Arc::new(DBAuthRepo {
            db_session: db_session.clone().unwrap(),
            expiry_hours: app_config.jwt_expiry_hours,
        })
    };

    let emails_repo: Arc<dyn EmailsRepo> = if app_config.mock_postmark {
        Arc::new(InMemoryEmailsRepo::default())
    } else {
        Arc::new(PostmarkEmailsRepo {
            client: Client::new(),
            archive_sender_email: app_config.archive_sender_email.clone(),
            api_key: app_config.postmark_api_key.clone(),
            postmark_api_base: app_config.postmark_api_base.clone(),
        })
    };

    let subjects_repo: Arc<dyn crate::repos::subjects_repo::SubjectsRepo> = if app_config.mock_db {
        Arc::new(InMemorySubjectsRepo::default())
    } else {
        Arc::new(DBSubjectsRepo {
            db_session: db_session.clone().unwrap(),
        })
    };

    let locations_repo: Arc<dyn crate::repos::locations_repo::LocationsRepo> = if app_config.mock_db
    {
        Arc::new(InMemoryLocationsRepo::default())
    } else {
        Arc::new(DBLocationsRepo {
            db_session: db_session.clone().unwrap(),
        })
    };

    let relations_repo: Arc<dyn crate::repos::relations_repo::RelationsRepo> = if app_config.mock_db
    {
        Arc::new(InMemoryRelationsRepo::default())
    } else {
        Arc::new(DBRelationsRepo {
            db_session: db_session.clone().unwrap(),
        })
    };

    let creators_repo: Arc<dyn crate::repos::creators_repo::CreatorsRepo> = if app_config.mock_db {
        Arc::new(InMemoryCreatorsRepo::default())
    } else {
        Arc::new(DBCreatorsRepo {
            db_session: db_session.clone().unwrap(),
        })
    };

    let contributors_repo: Arc<dyn crate::repos::contributors_repo::ContributorsRepo> =
        if app_config.mock_db {
            Arc::new(InMemoryContributorsRepo::default())
        } else {
            Arc::new(DBContributorsRepo {
                db_session: db_session.clone().unwrap(),
            })
        };

    let contributor_roles_repo: Arc<
        dyn crate::repos::contributor_roles_repo::ContributorRolesRepo,
    > = if app_config.mock_db {
        Arc::new(InMemoryContributorRolesRepo::default())
    } else {
        Arc::new(DBContributorRolesRepo {
            db_session: db_session.clone().unwrap(),
        })
    };

    let collections_repo: Arc<dyn crate::repos::collections_repo::CollectionsRepo> =
        if app_config.mock_db {
            Arc::new(InMemoryCollectionsRepo::default())
        } else {
            Arc::new(DBCollectionsRepo {
                db_session: db_session.clone().unwrap(),
            })
        };

    let browsertrix_repo: Arc<dyn BrowsertrixRepo> = if app_config.mock_browsertrix {
        Arc::new(InMemoryBrowsertrixRepo::new())
    } else {
        let mut repo = HTTPBrowsertrixRepo {
            client: Client::new(),
            login_url: app_config.browsertrix.login_url.clone(),
            username: app_config.browsertrix.username.clone(),
            password: app_config.browsertrix.password.clone(),
            base_url: app_config.browsertrix.base_url.clone(),
            org_id: app_config.browsertrix.org_id,
            access_token: Arc::new(RwLock::new(String::new())),
            create_crawl_url: app_config.browsertrix.create_crawl_url.clone(),
        };
        repo.initialize().await;
        Arc::new(repo)
    };

    let s3_repo: Arc<dyn S3Repo> = if app_config.mock_s3 {
        Arc::new(InMemoryS3Repo::new())
    } else {
        Arc::new(
            DigitalOceanSpacesRepo::new(
                app_config.digital_ocean_spaces_bucket.clone(),
                &app_config.digital_ocean_spaces_endpoint_url,
                &app_config.digital_ocean_spaces_access_key,
                &app_config.digital_ocean_spaces_secret_key,
                app_config.s3_operation_timeout,
                app_config.s3_operation_attempt_timeout,
                app_config.s3_connect_timeout,
            )
            .await?,
        )
    };

    let subjects_service = SubjectsService {
        subjects_repo: subjects_repo.clone(),
    };
    let locations_service = LocationsService {
        locations_repo: locations_repo.clone(),
    };
    let creators_service = CreatorsService {
        creators_repo: creators_repo.clone(),
    };
    let contributors_service = ContributorsService {
        contributors_repo: contributors_repo.clone(),
        contributor_roles_repo: contributor_roles_repo.clone(),
    };
    let relations_service = RelationsService {
        relations_repo: relations_repo.clone(),
    };
    let accessions_service = AccessionsService {
        accessions_repo,
        auth_repo: auth_repo.clone(),
        browsertrix_repo,
        emails_repo: emails_repo.clone(),
        s3_repo,
        subjects_service: subjects_service.clone(),
        locations_service: locations_service.clone(),
        creators_service: creators_service.clone(),
        contributors_service: contributors_service.clone(),
        presigned_put_url_expiry_seconds: app_config.presigned_put_url_expiry_seconds,
        presigned_get_url_expiry_seconds: app_config.presigned_get_url_expiry_seconds,
    };
    let auth_service = AuthService {
        auth_repo,
        emails_repo,
        jwt_cookie_domain: app_config.jwt_cookie_domain.clone(),
    };
    let collections_service = CollectionsService {
        collections_repo,
        subjects_repo,
    };
    let app_state = AppState {
        accessions_service,
        auth_service,
        collections_service,
        subjects_service,
        locations_service,
        creators_service,
        contributors_service,
        relations_service,
    };
    Ok((app_state, app_config.clone()))
}

/// Creates and configures the main application router with middleware and routes.
///
/// # Arguments
/// * `app_state` - Shared application state containing service instances
/// * `app_config` - Application configuration (controls rate limiting and tracing via ENABLE_* vars)
///
/// # Returns
/// Configured Router instance with all routes, middleware, and rate limiting
pub fn create_app(app_state: AppState, app_config: AppConfig) -> Router {
    let subscriber = tracing_subscriber::fmt().with_target(false).pretty();
    // turn on if you want more verbose logs
    // .with_max_level(tracing::Level::DEBUG);

    // this is a pain but it's because the tests are run in different threads
    // when you do cargo test; see
    // https://github.com/tokio-rs/console/issues/505
    if app_config.enable_tracing {
        subscriber.init();
    } else {
        subscriber.set_default();
    }
    let governor_conf = Arc::new(GovernorConfig::default());
    let governor_limiter = governor_conf.limiter().clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(60));
        tracing::info!("rate limiting storage size: {}", governor_limiter.len());
        governor_limiter.retain_recent();
    });
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::PUT])
        .allow_origin(app_config.cors_urls.clone())
        .allow_headers([CONTENT_TYPE])
        .allow_credentials(true);
    let all_routes: Router<AppState> = build_routes(ApiDoc::openapi(), app_config.clone());
    let base_routes = all_routes.layer(cors);
    // rate limiting can be disabled via ENABLE_RATE_LIMITING=false
    if app_config.enable_rate_limiting {
        base_routes
            .layer(GovernorLayer {
                config: governor_conf,
            })
            .with_state(app_state)
    } else {
        base_routes.with_state(app_state)
    }
}

/// Builds the application routes with middleware stack.
///
/// Configures:
/// - Request tracing with method and path logging
/// - 120 second timeout
/// - Response compression
/// - JSON content type validation
/// - Health check endpoint
/// - API routes
fn build_routes(api: utoipa::openapi::OpenApi, app_config: AppConfig) -> Router<AppState> {
    let middleware = ServiceBuilder::new()
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request<_>| {
                let matched_path = request
                    .extensions()
                    .get::<MatchedPath>()
                    .map(MatchedPath::as_str);
                // add fields to different logs here
                info_span!(
                    "http_request",
                    method = ?request.method(),
                    request_path = matched_path,
                )
            }),
        )
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(120),
        ))
        .layer(CompressionLayer::new());
    let accessions_routes = get_accessions_routes();
    let collections_routes = get_collections_routes();
    let subjects_routes = get_subjects_routes();
    let locations_routes = get_locations_routes();
    let creators_routes = get_creators_routes();
    let contributors_routes = get_contributors_routes();
    let auth_routes = get_auth_routes();
    let relations_routes = get_relations_routes();
    let api_prefix = app_config.api_prefix.clone();
    let swagger_ui = SwaggerUi::new("/")
        .url("/openapi.json", api.clone())
        .config(Config::from(format!(
            "{}/docs/openapi.json",
            app_config.api_prefix
        )));

    let api_v1 = Router::new()
        .merge(accessions_routes)
        .merge(collections_routes)
        .merge(subjects_routes)
        .merge(locations_routes)
        .merge(creators_routes)
        .merge(contributors_routes)
        .merge(auth_routes)
        .merge(relations_routes);
    Router::new()
        .nest("/docs/", swagger_ui.into())
        .route(
            "/docs",
            // This is a pain but required because Swagger registers to /docs/ but I forget this and always
            // navigate to just /docs and get a 404
            get(move || async move { Redirect::to(&format!("{}/docs/", api_prefix)) }),
        )
        .nest("/api/v1", api_v1)
        .route("/health", get(healthcheck))
        .layer(middleware)
}
