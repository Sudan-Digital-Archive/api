//! Routes for managing Dublin Metadata Contributors and their roles.
//! These act somewhat like 'tags'; they constitute a limited keyword vocabulary of contributor descriptors
//! for accessions.
//!
//! This module provides HTTP endpoints for creating, and listing contributors and their roles.

use crate::app_factory::AppState;
use crate::auth::{validate_at_least_contributor, validate_at_least_researcher};
use crate::models::auth::AuthenticatedUser;
use crate::models::request::{
    ContributorLangParam, ContributorPagination, ContributorRoleLangParam,
    ContributorRolePagination, CreateContributorRequest, CreateContributorRoleRequest,
    DeleteContributorRequest, DeleteContributorRoleRequest, UpdateContributorRequest,
    UpdateContributorRoleRequest,
};
use crate::models::response::{
    ContributorResponse, ContributorRoleResponse, ListContributorRolesArResponse,
    ListContributorRolesEnResponse, ListContributorsArResponse, ListContributorsEnResponse,
};
use ::entity::sea_orm_active_enums::Role;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use validator::Validate;

pub fn get_contributors_routes() -> Router<AppState> {
    Router::new().nest(
        "/contributors",
        Router::new()
            .route("/", get(list_contributors))
            .route("/", post(create_contributor))
            .route("/{contributor_id}", get(get_one_contributor))
            .route("/{contributor_id}", delete(delete_contributor))
            .route("/{contributor_id}", put(update_contributor))
            .nest(
                "/roles",
                Router::new()
                    .route("/", get(list_roles))
                    .route("/", post(create_role))
                    .route("/{role_id}", get(get_one_role))
                    .route("/{role_id}", delete(delete_role))
                    .route("/{role_id}", put(update_role)),
            ),
    )
}

#[utoipa::path(
    post,
    path = "/api/v1/contributors",
    tag = "Contributors",
    request_body = CreateContributorRequest,
    responses(
        (status = 201, description = "Created", body = ContributorResponse),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden")
    ),
    security(
        ("jwt_cookie_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn create_contributor(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
    Json(payload): Json<CreateContributorRequest>,
) -> Response {
    if !validate_at_least_contributor(&authenticated_user.role) {
        return (StatusCode::FORBIDDEN, "Must have at least contributor role").into_response();
    }
    if let Err(err) = payload.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }
    state.contributors_service.create_one(payload).await
}

#[utoipa::path(
    get,
    path = "/api/v1/contributors",
    tag = "Contributors",
    params(
        ContributorPagination
    ),
    responses(
        (status = 200, description = "OK", body = ListContributorsEnResponse, content_type = "application/json"),
        (status = 200, description = "OK", body = ListContributorsArResponse, content_type = "application/json"),
        (status = 400, description = "Bad request")
    )
)]
async fn list_contributors(
    State(state): State<AppState>,
    pagination: Query<ContributorPagination>,
) -> Response {
    if let Err(err) = pagination.0.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }
    state
        .contributors_service
        .list(
            pagination.0.page,
            pagination.0.per_page,
            pagination.0.lang,
            pagination.0.query_term,
        )
        .await
}

#[utoipa::path(
    get,
    path = "/api/v1/contributors/{contributor_id}",
    tag = "Contributors",
    params(
        ("contributor_id" = i32, Path, description = "Contributor ID"),
        ContributorLangParam
    ),
    responses(
        (status = 200, description = "OK", body = ContributorResponse),
        (status = 404, description = "Not found")
    )
)]
async fn get_one_contributor(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    Query(params): Query<ContributorLangParam>,
) -> Response {
    state.contributors_service.get_one(id, params.lang).await
}

#[utoipa::path(
    delete,
    path = "/api/v1/contributors/{contributor_id}",
    tag = "Contributors",
    request_body = DeleteContributorRequest,
    responses(
        (status = 200, description = "Contributor deleted"),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found")
    ),
    security(
        ("jwt_cookie_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn delete_contributor(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    authenticated_user: AuthenticatedUser,
    Json(payload): Json<DeleteContributorRequest>,
) -> Response {
    if authenticated_user.role != Role::Admin {
        return (StatusCode::FORBIDDEN, "Insufficient permissions").into_response();
    }
    if let Err(err) = payload.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }
    state
        .contributors_service
        .delete_one(id, payload.lang)
        .await
}

#[utoipa::path(
    put,
    path = "/api/v1/contributors/{contributor_id}",
    tag = "Contributors",
    request_body = UpdateContributorRequest,
    responses(
        (status = 200, description = "OK", body = ContributorResponse),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found")
    ),
    security(
        ("jwt_cookie_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn update_contributor(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    authenticated_user: AuthenticatedUser,
    Json(payload): Json<UpdateContributorRequest>,
) -> Response {
    if !validate_at_least_researcher(&authenticated_user.role) {
        return (StatusCode::FORBIDDEN, "Must have at least researcher role").into_response();
    }
    if let Err(err) = payload.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }
    state.contributors_service.update_one(id, payload).await
}

#[utoipa::path(
    post,
    path = "/api/v1/contributors/roles",
    tag = "Contributors",
    request_body = CreateContributorRoleRequest,
    responses(
        (status = 201, description = "Created", body = ContributorRoleResponse),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden")
    ),
    security(
        ("jwt_cookie_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn create_role(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
    Json(payload): Json<CreateContributorRoleRequest>,
) -> Response {
    if !validate_at_least_contributor(&authenticated_user.role) {
        return (StatusCode::FORBIDDEN, "Must have at least contributor role").into_response();
    }
    if let Err(err) = payload.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }
    state.contributors_service.create_role(payload).await
}

#[utoipa::path(
    get,
    path = "/api/v1/contributors/roles",
    tag = "Contributors",
    params(
        ContributorRolePagination
    ),
    responses(
        (status = 200, description = "OK", body = ListContributorRolesEnResponse, content_type = "application/json"),
        (status = 200, description = "OK", body = ListContributorRolesArResponse, content_type = "application/json"),
        (status = 400, description = "Bad request")
    )
)]
async fn list_roles(
    State(state): State<AppState>,
    pagination: Query<ContributorRolePagination>,
) -> Response {
    if let Err(err) = pagination.0.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }
    state
        .contributors_service
        .list_roles(
            pagination.0.page,
            pagination.0.per_page,
            pagination.0.lang,
            pagination.0.query_term,
        )
        .await
}

#[utoipa::path(
    get,
    path = "/api/v1/contributors/roles/{role_id}",
    tag = "Contributors",
    params(
        ("role_id" = i32, Path, description = "Role ID"),
        ContributorRoleLangParam
    ),
    responses(
        (status = 200, description = "OK", body = ContributorRoleResponse),
        (status = 404, description = "Not found")
    )
)]
async fn get_one_role(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    Query(params): Query<ContributorRoleLangParam>,
) -> Response {
    state.contributors_service.get_role(id, params.lang).await
}

#[utoipa::path(
    delete,
    path = "/api/v1/contributors/roles/{role_id}",
    tag = "Contributors",
    request_body = DeleteContributorRoleRequest,
    responses(
        (status = 200, description = "Contributor role deleted"),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found")
    ),
    security(
        ("jwt_cookie_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn delete_role(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    authenticated_user: AuthenticatedUser,
    Json(payload): Json<DeleteContributorRoleRequest>,
) -> Response {
    if authenticated_user.role != Role::Admin {
        return (StatusCode::FORBIDDEN, "Insufficient permissions").into_response();
    }
    if let Err(err) = payload.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }
    state
        .contributors_service
        .delete_role(id, payload.lang)
        .await
}

#[utoipa::path(
    put,
    path = "/api/v1/contributors/roles/{role_id}",
    tag = "Contributors",
    request_body = UpdateContributorRoleRequest,
    responses(
        (status = 200, description = "OK", body = ContributorRoleResponse),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found")
    ),
    security(
        ("jwt_cookie_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn update_role(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    authenticated_user: AuthenticatedUser,
    Json(payload): Json<UpdateContributorRoleRequest>,
) -> Response {
    if !validate_at_least_researcher(&authenticated_user.role) {
        return (StatusCode::FORBIDDEN, "Must have at least researcher role").into_response();
    }
    if let Err(err) = payload.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }
    state.contributors_service.update_role(id, payload).await
}

#[cfg(test)]
mod tests {

    use crate::models::response::{
        ContributorResponse, ContributorRoleResponse, ListContributorRolesArResponse,
        ListContributorRolesEnResponse, ListContributorsArResponse, ListContributorsEnResponse,
    };
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
    async fn create_one_contributor_no_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/contributors")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "lang": "english",
                            "contributor": "Test Contributor"
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
    async fn create_one_contributor_en() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/contributors")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header(http::header::COOKIE, format!("jwt={}", get_mock_jwt()))
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "lang": "english",
                            "contributor": "Test Contributor"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: ContributorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(actual.contributor, "Test Contributor".to_string());
    }

    #[tokio::test]
    async fn create_one_contributor_ar() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/contributors")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header(http::header::COOKIE, format!("jwt={}", get_mock_jwt()))
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "lang": "arabic",
                            "contributor": "مختبر"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: ContributorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(actual.contributor, "مختبر".to_string());
    }

    #[tokio::test]
    async fn list_contributors_en() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/contributors?page=0&per_page=1&lang=english")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: ListContributorsEnResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(actual.num_pages, 10);
        assert_eq!(actual.items.len(), 1);
    }

    #[tokio::test]
    async fn list_contributors_ar() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/contributors?page=0&per_page=1&lang=arabic")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: ListContributorsArResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(actual.num_pages, 10);
        assert_eq!(actual.items.len(), 1);
    }

    #[tokio::test]
    async fn delete_one_contributor_no_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri("/api/v1/contributors/1")
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
    async fn delete_one_contributor_with_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri("/api/v1/contributors/1")
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
    async fn update_one_contributor_no_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri("/api/v1/contributors/1")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "lang": "english",
                            "contributor": "updated contributor"
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
    async fn update_one_contributor_with_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri("/api/v1/contributors/1")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header(http::header::COOKIE, format!("jwt={}", get_mock_jwt()))
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "lang": "english",
                            "contributor": "updated contributor"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: ContributorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(actual.contributor, "updated contributor".to_string());
        assert_eq!(actual.id, 1);
    }

    #[tokio::test]
    async fn create_one_role_no_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/contributors/roles")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "lang": "english",
                            "role": "Photographer"
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
    async fn create_one_role_en() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/contributors/roles")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header(http::header::COOKIE, format!("jwt={}", get_mock_jwt()))
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "lang": "english",
                            "role": "Photographer"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: ContributorRoleResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(actual.role, "Photographer".to_string());
    }

    #[tokio::test]
    async fn list_roles_en() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/contributors/roles?page=0&per_page=1&lang=english")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: ListContributorRolesEnResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(actual.num_pages, 10);
        assert_eq!(actual.items.len(), 1);
    }

    #[tokio::test]
    async fn list_roles_ar() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/contributors/roles?page=0&per_page=1&lang=arabic")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: ListContributorRolesArResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(actual.num_pages, 10);
        assert_eq!(actual.items.len(), 1);
    }

    #[tokio::test]
    async fn delete_one_role_no_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri("/api/v1/contributors/roles/1")
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
    async fn delete_one_role_with_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri("/api/v1/contributors/roles/1")
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
    async fn update_one_role_no_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri("/api/v1/contributors/roles/1")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "lang": "english",
                            "role": "updated role"
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
    async fn update_one_role_with_auth() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri("/api/v1/contributors/roles/1")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .header(http::header::COOKIE, format!("jwt={}", get_mock_jwt()))
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "lang": "english",
                            "role": "updated role"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: ContributorRoleResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(actual.role, "updated role".to_string());
        assert_eq!(actual.id, 1);
    }
}
