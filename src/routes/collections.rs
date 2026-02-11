//! Routes for managing collections in the digital archive.
//!
//! This module provides HTTP endpoints for creating, retrieving, updating, and deleting collections.
//! It uses in-memory repositories for testing to avoid I/O operations.

use crate::app_factory::AppState;
use crate::auth::{validate_at_least_contributor, validate_at_least_researcher};
use crate::models::auth::AuthenticatedUser;
use crate::models::request::{
    CollectionLangParam, CollectionPagination, CollectionPaginationWithPrivate,
    CreateCollectionRequest, UpdateCollectionRequest,
};
use crate::models::response::{CollectionResponse, ListCollectionsResponse};
use ::entity::sea_orm_active_enums::Role;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use validator::Validate;

/// Creates routes for collection-related endpoints under `/collections`.
pub fn get_collections_routes() -> Router<AppState> {
    Router::new().nest(
        "/collections",
        Router::new()
            .route("/", get(list_collections))
            .route("/private", get(list_collections_private))
            .route("/", post(create_collection))
            .route("/{collection_id}", get(get_one_collection))
            .route("/{collection_id}", put(update_collection))
            .route("/{collection_id}", delete(delete_collection)),
    )
}

#[utoipa::path(
    get,
    path = "/api/v1/collections",
    tag = "Collections",
    params(
        CollectionPagination
    ),
    responses(
        (status = 200, description = "OK", body = ListCollectionsResponse),
        (status = 400, description = "Bad request")
    )
)]
async fn list_collections(
    State(state): State<AppState>,
    pagination: Query<CollectionPagination>,
) -> Response {
    if let Err(err) = pagination.0.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }
    state
        .collections_service
        .list(
            pagination.0.lang,
            pagination.0.page,
            pagination.0.per_page,
            Some(true),
        )
        .await
}

#[utoipa::path(
    get,
    path = "/api/v1/collections/private",
    tag = "Collections",
    params(
        CollectionPaginationWithPrivate
    ),
    responses(
        (status = 200, description = "OK", body = ListCollectionsResponse),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden")
    ),
    security(
        ("jwt_cookie_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn list_collections_private(
    State(state): State<AppState>,
    pagination: Query<CollectionPaginationWithPrivate>,
    authenticated_user: AuthenticatedUser,
) -> Response {
    if !validate_at_least_contributor(&authenticated_user.role) {
        return (StatusCode::FORBIDDEN, "Must have at least contributor role").into_response();
    }
    if let Err(err) = pagination.0.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }
    state
        .collections_service
        .list(
            pagination.0.lang,
            pagination.0.page,
            pagination.0.per_page,
            pagination.0.is_private,
        )
        .await
}

#[utoipa::path(
    get,
    path = "/api/v1/collections/{collection_id}",
    tag = "Collections",
    params(
        ("collection_id" = i32, Path, description = "Collection ID"),
        CollectionLangParam
    ),
    responses(
        (status = 200, description = "OK", body = CollectionResponse),
        (status = 404, description = "Not found")
    )
)]
async fn get_one_collection(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    Query(params): Query<CollectionLangParam>,
) -> Response {
    state.collections_service.get_one(id, params.lang).await
}

#[utoipa::path(
    post,
    path = "/api/v1/collections",
    tag = "Collections",
    request_body = CreateCollectionRequest,
    responses(
        (status = 201, description = "Collection created"),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden")
    ),
    security(
        ("jwt_cookie_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn create_collection(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
    Json(payload): Json<CreateCollectionRequest>,
) -> Response {
    if !validate_at_least_contributor(&authenticated_user.role) {
        return (StatusCode::FORBIDDEN, "Must have at least contributor role").into_response();
    }
    if let Err(err) = payload.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }
    state
        .collections_service
        .create_one(
            payload.title,
            payload.description,
            payload.is_public,
            payload.subject_ids,
            payload.lang,
        )
        .await
}

#[utoipa::path(
    put,
    path = "/api/v1/collections/{collection_id}",
    tag = "Collections",
    request_body = UpdateCollectionRequest,
    responses(
        (status = 200, description = "OK", body = CollectionResponse),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found")
    ),
    security(
        ("jwt_cookie_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn update_collection(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    authenticated_user: AuthenticatedUser,
    Json(payload): Json<UpdateCollectionRequest>,
) -> Response {
    if !validate_at_least_researcher(&authenticated_user.role) {
        return (StatusCode::FORBIDDEN, "Must have at least researcher role").into_response();
    }
    if let Err(err) = payload.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }
    state
        .collections_service
        .update_one(
            id,
            payload.title,
            payload.description,
            payload.is_public,
            payload.subject_ids,
            payload.lang,
        )
        .await
}

#[utoipa::path(
    delete,
    path = "/api/v1/collections/{collection_id}",
    tag = "Collections",
    params(
        ("collection_id" = i32, Path, description = "Collection ID"),
        CollectionLangParam
    ),
    responses(
        (status = 200, description = "Collection deleted"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found")
    ),
    security(
        ("jwt_cookie_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn delete_collection(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    authenticated_user: AuthenticatedUser,
    Query(params): Query<CollectionLangParam>,
) -> Response {
    if authenticated_user.role != Role::Admin {
        return (StatusCode::FORBIDDEN, "Insufficient permissions").into_response();
    }
    state.collections_service.delete_one(id, params.lang).await
}

#[cfg(test)]
mod tests {
    use crate::models::response::{CollectionResponse, ListCollectionsResponse};
    use crate::test_tools::{build_test_app, get_mock_jwt};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use tower::ServiceExt;

    #[tokio::test]
    async fn list_collections_no_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/collections")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn list_collections_with_pagination() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/collections?page=0&per_page=1&lang=english")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: ListCollectionsResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(actual.page, 0);
        assert_eq!(actual.per_page, 1);
    }

    #[tokio::test]
    async fn list_collections_private_no_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/collections/private")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn list_collections_private_with_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/collections/private?page=0&per_page=1&lang=english&is_private=true")
                    .header(http::header::COOKIE, format!("jwt={}", get_mock_jwt()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_one_collection() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/collections/1?lang=english")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn create_collection_no_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/collections")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "lang": "english",
                            "title": "Test Collection",
                            "description": "A test collection",
                            "is_public": true,
                            "subject_ids": [1, 2]
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
    async fn create_collection_with_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/collections")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header(http::header::COOKIE, format!("jwt={}", get_mock_jwt()))
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "lang": "english",
                            "title": "Test Collection",
                            "description": "A test collection",
                            "is_public": true,
                            "subject_ids": [1, 2]
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual = String::from_utf8((&body).to_vec()).unwrap();
        assert!(actual.contains("Collection created with id"));
    }

    #[tokio::test]
    async fn update_collection_no_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri("/api/v1/collections/1")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "lang": "english",
                            "title": "Updated Collection",
                            "description": "An updated collection",
                            "is_public": false,
                            "subject_ids": [3]
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
    async fn update_collection_with_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri("/api/v1/collections/1")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header(http::header::COOKIE, format!("jwt={}", get_mock_jwt()))
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "lang": "english",
                            "title": "Updated Collection",
                            "description": "An updated collection",
                            "is_public": false,
                            "subject_ids": [3]
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: CollectionResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(actual.title, "Mock Collection");
    }

    #[tokio::test]
    async fn delete_collection_no_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri("/api/v1/collections/1?lang=english")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn delete_collection_with_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri("/api/v1/collections/1?lang=english")
                    .header(http::header::COOKIE, format!("jwt={}", get_mock_jwt()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual = String::from_utf8((&body).to_vec()).unwrap();
        assert_eq!(actual, "Collection deleted");
    }
}
