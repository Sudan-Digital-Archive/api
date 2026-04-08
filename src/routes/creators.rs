//! Routes for managing Dublin Metadata Creators.
//! These act somewhat like 'tags'; they constitute a limited keyword vocabulary of creator descriptors
//! for accessions.
//!
//! This module provides HTTP endpoints for creating, and listing creators.

use crate::app_factory::AppState;
use crate::auth::{validate_at_least_contributor, validate_at_least_researcher};
use crate::models::auth::AuthenticatedUser;
use crate::models::request::{
    CreateCreatorRequest, CreatorLangParam, CreatorPagination, DeleteCreatorRequest,
    UpdateCreatorRequest,
};
use crate::models::response::{CreatorResponse, ListCreatorsResponse};
use ::entity::sea_orm_active_enums::Role;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use validator::Validate;

pub fn get_creators_routes() -> Router<AppState> {
    Router::new().nest(
        "/creators",
        Router::new()
            .route("/", get(list_creators))
            .route("/", post(create_creator))
            .route("/{creator_id}", get(get_one_creator))
            .route("/{creator_id}", delete(delete_creator))
            .route("/{creator_id}", put(update_creator)),
    )
}

#[utoipa::path(
    post,
    path = "/api/v1/creators",
    tag = "Creators",
    request_body = CreateCreatorRequest,
    responses(
        (status = 201, description = "Created", body = CreatorResponse),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden")
    ),
    security(
        ("jwt_cookie_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn create_creator(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
    Json(payload): Json<CreateCreatorRequest>,
) -> Response {
    if !validate_at_least_contributor(&authenticated_user.role) {
        return (StatusCode::FORBIDDEN, "Must have at least contributor role").into_response();
    }
    if let Err(err) = payload.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }
    state.creators_service.create_one(payload).await
}

#[utoipa::path(
    get,
    path = "/api/v1/creators",
    tag = "Creators",
    params(
        CreatorPagination
    ),
    responses(
        (status = 200, description = "OK", body = ListCreatorsResponse)
    )
)]
async fn list_creators(
    State(state): State<AppState>,
    pagination: Query<CreatorPagination>,
) -> Response {
    if let Err(err) = pagination.0.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }
    state
        .creators_service
        .list(
            pagination.0.page,
            pagination.0.per_page,
            pagination.0.lang,
            pagination.0.query_term,
            pagination.0.in_collection_id,
        )
        .await
}

#[utoipa::path(
    get,
    path = "/api/v1/creators/{creator_id}",
    tag = "Creators",
    params(
        ("creator_id" = i32, Path, description = "Creator ID"),
        CreatorLangParam
    ),
    responses(
        (status = 200, description = "OK", body = CreatorResponse),
        (status = 404, description = "Not found")
    )
)]
async fn get_one_creator(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    Query(params): Query<CreatorLangParam>,
) -> Response {
    state.creators_service.get_one(id, params.lang).await
}

#[utoipa::path(
    delete,
    path = "/api/v1/creators/{creator_id}",
    tag = "Creators",
    request_body = DeleteCreatorRequest,
    responses(
        (status = 200, description = "Creator deleted"),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found")
    ),
    security(
        ("jwt_cookie_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn delete_creator(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    authenticated_user: AuthenticatedUser,
    Json(payload): Json<DeleteCreatorRequest>,
) -> Response {
    if authenticated_user.role != Role::Admin {
        return (StatusCode::FORBIDDEN, "Insufficient permissions").into_response();
    }
    if let Err(err) = payload.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }
    state.creators_service.delete_one(id, payload.lang).await
}

#[utoipa::path(
    put,
    path = "/api/v1/creators/{creator_id}",
    tag = "Creators",
    request_body = UpdateCreatorRequest,
    responses(
        (status = 200, description = "OK", body = CreatorResponse),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found")
    ),
    security(
        ("jwt_cookie_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn update_creator(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    authenticated_user: AuthenticatedUser,
    Json(payload): Json<UpdateCreatorRequest>,
) -> Response {
    if !validate_at_least_researcher(&authenticated_user.role) {
        return (StatusCode::FORBIDDEN, "Must have at least researcher role").into_response();
    }
    if let Err(err) = payload.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }
    state.creators_service.update_one(id, payload).await
}

#[cfg(test)]
mod tests {
    use crate::models::response::{CreatorResponse, ListCreatorsResponse};
    use crate::test_tools::{build_test_app, get_mock_jwt};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use tower::ServiceExt;

    fn mock_paginated_creators_en() -> (Vec<CreatorResponse>, u64) {
        (
            vec![CreatorResponse {
                id: 1,
                creator: "Test Creator".to_string(),
            }],
            10,
        )
    }

    fn mock_paginated_creators_ar() -> (Vec<CreatorResponse>, u64) {
        (
            vec![CreatorResponse {
                id: 1,
                creator: "مختبر".to_string(),
            }],
            10,
        )
    }

    #[tokio::test]
    async fn create_one_creator_no_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/creators")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "lang": "english",
                            "creator": "Test Creator"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn create_one_creator_en() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/creators")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header(http::header::COOKIE, format!("jwt={}", get_mock_jwt()))
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "lang": "english",
                            "creator": "Test Creator"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: CreatorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(actual.creator, "Test Creator".to_string());
    }

    #[tokio::test]
    async fn create_one_creator_ar() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/creators")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header(http::header::COOKIE, format!("jwt={}", get_mock_jwt()))
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "lang": "arabic",
                            "creator": "مختبر"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: CreatorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(actual.creator, "مختبر".to_string());
    }

    #[tokio::test]
    async fn list_creators_en() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/creators?page=0&per_page=1&lang=english")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: ListCreatorsResponse = serde_json::from_slice(&body).unwrap();
        let mocked_resp = mock_paginated_creators_en();
        assert_eq!(actual.num_pages, mocked_resp.1);
        assert_eq!(actual.items.len(), mocked_resp.0.len());
    }

    #[tokio::test]
    async fn list_creators_ar() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/creators?page=0&per_page=1&lang=arabic")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: ListCreatorsResponse = serde_json::from_slice(&body).unwrap();
        let mocked_resp = mock_paginated_creators_ar();
        assert_eq!(actual.num_pages, mocked_resp.1);
        assert_eq!(actual.items.len(), mocked_resp.0.len());
    }

    #[tokio::test]
    async fn delete_one_creator_no_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri("/api/v1/creators/1")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "lang": "arabic",
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn delete_one_creator_with_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri("/api/v1/creators/1")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header(http::header::COOKIE, format!("jwt={}", get_mock_jwt()))
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "lang": "english",
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn update_one_creator_no_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri("/api/v1/creators/1")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "lang": "english",
                            "creator": "updated creator"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn update_one_creator_with_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri("/api/v1/creators/1")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header(http::header::COOKIE, format!("jwt={}", get_mock_jwt()))
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "lang": "english",
                            "creator": "updated creator"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: CreatorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(actual.creator, "updated creator".to_string());
        assert_eq!(actual.id, 1);
    }
}
