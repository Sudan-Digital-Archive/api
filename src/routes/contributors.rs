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
