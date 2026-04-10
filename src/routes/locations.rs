//! Routes for managing Dublin Metadata Locations.
//! These act somewhat like 'tags'; they constitute a limited keyword vocabulary of location descriptors
//! for accessions.
//!
//! This module provides HTTP endpoints for creating, and listing locations.

use crate::app_factory::AppState;
use crate::auth::{validate_at_least_contributor, validate_at_least_researcher};
use crate::models::auth::AuthenticatedUser;
use crate::models::request::{
    CreateLocationRequest, DeleteLocationRequest, LocationLangParam, LocationPagination,
    UpdateLocationRequest,
};
use crate::models::response::{ListLocationsResponse, LocationResponse};
use ::entity::sea_orm_active_enums::Role;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use validator::Validate;

pub fn get_locations_routes() -> Router<AppState> {
    Router::new().nest(
        "/locations",
        Router::new()
            .route("/", get(list_locations))
            .route("/", post(create_location))
            .route("/{location_id}", get(get_one_location))
            .route("/{location_id}", delete(delete_location))
            .route("/{location_id}", put(update_location)),
    )
}

#[utoipa::path(
    post,
    path = "/api/v1/locations",
    tag = "Locations",
    request_body = CreateLocationRequest,
    responses(
        (status = 201, description = "Created", body = LocationResponse),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden")
    ),
    security(
        ("jwt_cookie_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn create_location(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
    Json(payload): Json<CreateLocationRequest>,
) -> Response {
    if !validate_at_least_contributor(&authenticated_user.role) {
        return (StatusCode::FORBIDDEN, "Must have at least contributor role").into_response();
    }
    if let Err(err) = payload.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }
    state.locations_service.create_one(payload).await
}

#[utoipa::path(
    get,
    path = "/api/v1/locations",
    tag = "Locations",
    params(
        LocationPagination
    ),
    responses(
        (status = 200, description = "OK", body = ListLocationsResponse)
    )
)]
async fn list_locations(
    State(state): State<AppState>,
    pagination: Query<LocationPagination>,
) -> Response {
    if let Err(err) = pagination.0.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }
    state
        .locations_service
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
    path = "/api/v1/locations/{location_id}",
    tag = "Locations",
    params(
        ("location_id" = i32, Path, description = "Location ID"),
        LocationLangParam
    ),
    responses(
        (status = 200, description = "OK", body = LocationResponse),
        (status = 404, description = "Not found")
    )
)]
async fn get_one_location(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    Query(params): Query<LocationLangParam>,
) -> Response {
    state.locations_service.get_one(id, params.lang).await
}

#[utoipa::path(
    delete,
    path = "/api/v1/locations/{location_id}",
    tag = "Locations",
    request_body = DeleteLocationRequest,
    responses(
        (status = 200, description = "Location deleted"),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found")
    ),
    security(
        ("jwt_cookie_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn delete_location(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    authenticated_user: AuthenticatedUser,
    Json(payload): Json<DeleteLocationRequest>,
) -> Response {
    if authenticated_user.role != Role::Admin {
        return (StatusCode::FORBIDDEN, "Insufficient permissions").into_response();
    }
    if let Err(err) = payload.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }
    state.locations_service.delete_one(id, payload.lang).await
}

#[utoipa::path(
    put,
    path = "/api/v1/locations/{location_id}",
    tag = "Locations",
    request_body = UpdateLocationRequest,
    responses(
        (status = 200, description = "OK", body = LocationResponse),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found")
    ),
    security(
        ("jwt_cookie_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn update_location(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    authenticated_user: AuthenticatedUser,
    Json(payload): Json<UpdateLocationRequest>,
) -> Response {
    if !validate_at_least_researcher(&authenticated_user.role) {
        return (StatusCode::FORBIDDEN, "Must have at least researcher role").into_response();
    }
    if let Err(err) = payload.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }
    state.locations_service.update_one(id, payload).await
}

#[cfg(test)]
mod tests {
    use crate::models::response::{ListLocationsResponse, LocationResponse};
    use crate::test_tools::{build_test_app, get_mock_jwt};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use tower::ServiceExt;

    fn mock_paginated_locations_en() -> (Vec<LocationResponse>, u64) {
        (
            vec![LocationResponse {
                id: 1,
                location: "Khartoum".to_string(),
            }],
            10,
        )
    }

    fn mock_paginated_locations_ar() -> (Vec<LocationResponse>, u64) {
        (
            vec![LocationResponse {
                id: 1,
                location: "الخرطوم".to_string(),
            }],
            10,
        )
    }

    #[tokio::test]
    async fn create_one_location_no_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/locations")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "lang": "english",
                            "location": "Khartoum"
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
    async fn create_one_location_en() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/locations")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header(http::header::COOKIE, format!("jwt={}", get_mock_jwt()))
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "lang": "english",
                            "location": "Khartoum"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: LocationResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(actual.location, "Khartoum".to_string());
    }

    #[tokio::test]
    async fn create_one_location_ar() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/locations")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header(http::header::COOKIE, format!("jwt={}", get_mock_jwt()))
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "lang": "arabic",
                            "location": "الخرطوم"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: LocationResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(actual.location, "الخرطوم".to_string());
    }

    #[tokio::test]
    async fn list_locations_en() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/locations?page=0&per_page=1&lang=english")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: ListLocationsResponse = serde_json::from_slice(&body).unwrap();
        let mocked_resp = mock_paginated_locations_en();
        assert_eq!(actual.num_pages, mocked_resp.1);
        assert_eq!(actual.items.len(), mocked_resp.0.len());
    }

    #[tokio::test]
    async fn list_locations_ar() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/locations?page=0&per_page=1&lang=arabic")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: ListLocationsResponse = serde_json::from_slice(&body).unwrap();
        let mocked_resp = mock_paginated_locations_ar();
        assert_eq!(actual.num_pages, mocked_resp.1);
        assert_eq!(actual.items.len(), mocked_resp.0.len());
    }

    #[tokio::test]
    async fn delete_one_location_no_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri("/api/v1/locations/1")
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
    async fn delete_one_location_with_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri("/api/v1/locations/1")
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
    async fn update_one_location_no_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri("/api/v1/locations/1")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "lang": "english",
                            "location": "updated location"
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
    async fn update_one_location_with_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri("/api/v1/locations/1")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header(http::header::COOKIE, format!("jwt={}", get_mock_jwt()))
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "lang": "english",
                            "location": "updated location"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: LocationResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(actual.location, "updated location".to_string());
        assert_eq!(actual.id, 1);
    }
}
