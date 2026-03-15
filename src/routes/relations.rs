//! Routes for managing Dublin Metadata Relations between accessions.

use crate::app_factory::AppState;
use crate::auth::{validate_at_least_contributor, validate_at_least_researcher};
use crate::models::auth::AuthenticatedUser;
use crate::models::request::{CreateRelationRequest, RelationLangParam};
use crate::models::response::RelationResponse;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use validator::Validate;

pub fn get_relations_routes() -> Router<AppState> {
    Router::new().nest(
        "/accessions",
        Router::new()
            .route("/{accession_id}/relation", post(create_relation))
            .route("/{accession_id}/relation", get(list_relations))
            .route(
                "/{accession_id}/relation/{relation_id}",
                get(get_one_relation),
            )
            .route(
                "/{accession_id}/relation/{relation_id}",
                delete(delete_relation),
            ),
    )
}

#[utoipa::path(
    post,
    path = "/api/v1/accessions/{accession_id}/relation",
    tag = "Relations",
    params(
        RelationLangParam
    ),
    request_body = CreateRelationRequest,
    responses(
        (status = 201, description = "Created", body = RelationResponse),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found")
    ),
    security(
        ("jwt_cookie_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn create_relation(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
    Path(accession_id): Path<i32>,
    Query(lang_param): Query<RelationLangParam>,
    Json(payload): Json<CreateRelationRequest>,
) -> Response {
    if !validate_at_least_contributor(&authenticated_user.role) {
        return (StatusCode::FORBIDDEN, "Must have at least contributor role").into_response();
    }
    if let Err(err) = payload.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }

    let metadata_id = match state
        .accessions_service
        .get_dublin_metadata_id(accession_id, lang_param.lang)
        .await
    {
        Ok(Some(id)) => id,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                format!("{} metadata not found for this accession", lang_param.lang),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                format!("{} metadata not found for this accession", lang_param.lang),
            )
                .into_response();
        }
    };

    state
        .relations_service
        .create_one(metadata_id, payload, lang_param.lang)
        .await
}

#[utoipa::path(
    get,
    path = "/api/v1/accessions/{accession_id}/relation",
    tag = "Relations",
    params(
        RelationLangParam
    ),
    responses(
        (status = 200, description = "OK", body = [RelationResponse]),
        (status = 404, description = "Not found")
    )
)]
async fn list_relations(
    State(state): State<AppState>,
    Path(accession_id): Path<i32>,
    Query(lang_param): Query<RelationLangParam>,
) -> Response {
    let metadata_id = match state
        .accessions_service
        .get_dublin_metadata_id(accession_id, lang_param.lang)
        .await
    {
        Ok(Some(id)) => id,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                format!("{} metadata not found for this accession", lang_param.lang),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                format!("{} metadata not found for this accession", lang_param.lang),
            )
                .into_response();
        }
    };

    state
        .relations_service
        .list(metadata_id, lang_param.lang)
        .await
}

#[utoipa::path(
    get,
    path = "/api/v1/accessions/{accession_id}/relation/{relation_id}",
    tag = "Relations",
    params(
        RelationLangParam
    ),
    responses(
        (status = 200, description = "OK", body = RelationResponse),
        (status = 404, description = "Not found")
    )
)]
async fn get_one_relation(
    State(state): State<AppState>,
    Path((_accession_id, relation_id)): Path<(i32, i32)>,
    Query(lang_param): Query<RelationLangParam>,
) -> Response {
    state
        .relations_service
        .get_one(relation_id, lang_param.lang)
        .await
}

#[utoipa::path(
    delete,
    path = "/api/v1/accessions/{accession_id}/relation/{relation_id}",
    tag = "Relations",
    params(
        RelationLangParam
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found")
    ),
    security(
        ("jwt_cookie_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn delete_relation(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
    Path((_accession_id, relation_id)): Path<(i32, i32)>,
    Query(lang_param): Query<RelationLangParam>,
) -> Response {
    if !validate_at_least_researcher(&authenticated_user.role) {
        return (StatusCode::FORBIDDEN, "Must have at least researcher role").into_response();
    }

    state
        .relations_service
        .delete_one(relation_id, lang_param.lang)
        .await
}
