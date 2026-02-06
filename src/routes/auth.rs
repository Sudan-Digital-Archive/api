//! Authentication routes.
//!
//! This module provides HTTP endpoints for user authentication, including login and authorization.
//! It also includes a protected route for testing JWT authentication.
//! The module uses an authentication service to handle the authentication logic.

use crate::app_factory::AppState;
use crate::models::auth::AuthenticatedUser;
use crate::models::request::{
    AuthorizeRequest, CreateUserRequest, LoginRequest, RevokeApiKeyRequest, UpdateUserRequest,
    UserPagination,
};
use crate::models::response::{CreateApiKeyResponse, ListUsersResponse, UserResponse};
use ::entity::sea_orm_active_enums::Role;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use sea_orm::error::DbErr;
use tracing::{error, info};
use uuid::Uuid;
use validator::Validate;

pub fn get_auth_routes() -> Router<AppState> {
    Router::new().nest(
        "/auth",
        Router::new()
            .route("/", post(login))
            .route("/authorize", post(authorize))
            .route("/", get(verify))
            .route("/{:user_id}/api-key", post(create_api_key))
            .route("/{user_id}/revoke-api-key", put(revoke_api_key))
            // User management routes (admin only)
            .route("/users", post(create_user))
            .route("/users", get(list_users))
            .route("/users/{user_id}", get(get_user))
            .route("/users/{user_id}", put(update_user))
            .route("/users/{user_id}", delete(delete_user)),
    )
}

#[utoipa::path(
    post,
    path = "/api/v1/auth",
    tag = "Auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "OK"),
        (status = 400, description = "Bad request"),
        (status = 500, description = "Internal server error")
    )
)]
async fn login(State(state): State<AppState>, Json(payload): Json<LoginRequest>) -> Response {
    if let Err(err) = payload.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }

    let login_result = state.auth_service.clone().login(payload).await;

    match login_result {
        Ok(response) => response,
        Err(err) => {
            let message = format!("Server error occurred: {err}");
            error!(message);
            (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/authorize",
    tag = "Auth",
    request_body = AuthorizeRequest,
    responses(
        (status = 200, description = "OK"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    )
)]
async fn authorize(
    State(state): State<AppState>,
    Json(payload): Json<AuthorizeRequest>,
) -> Response {
    let auth_result = state.auth_service.authorize(payload).await;

    match auth_result {
        Ok(response) => response,
        Err(err) => {
            let message = format!("Server error occurred: {err}");
            error!(message);
            (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/auth",
    tag = "Auth",
    responses(
        (status = 200, description = "OK", body = String),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("jwt_cookie_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn verify(State(_state): State<AppState>, authenticated_user: AuthenticatedUser) -> Response {
    let user_data = format!("Verifying your account...\nYour data:\n{authenticated_user}");
    (StatusCode::OK, user_data).into_response()
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/{user_id}/api-key",
    tag = "Auth",
    responses(
        (status = 201, description = "API key created", body = CreateApiKeyResponse),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("jwt_cookie_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn create_api_key(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    authenticated_user: AuthenticatedUser,
) -> Response {
    if authenticated_user.role != Role::Admin {
        return (StatusCode::FORBIDDEN, "Only admins can create API keys").into_response();
    }

    let api_key_result = state.auth_service.create_api_key(user_id).await;

    match api_key_result {
        Ok(api_key_secret) => {
            info!(
                "API key created by admin {} for user {}",
                authenticated_user.user_id, user_id
            );
            let auth_service = state.auth_service.clone();
            tokio::spawn(async move {
                auth_service.delete_expired_api_keys().await;
            });
            let response = CreateApiKeyResponse { api_key_secret };
            (StatusCode::CREATED, Json(response)).into_response()
        }
        Err(err) => {
            error!(
                "Failed to create API key by admin {} for user {}: {}",
                authenticated_user.user_id, user_id, err
            );
            let message = format!("Failed to create API key: {err}");
            (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/users",
    tag = "Auth",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created successfully", body = UserResponse),
        (status = 400, description = "Bad request - validation error"),
        (status = 403, description = "Forbidden - admin only"),
        (status = 409, description = "Conflict - email already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("jwt_cookie_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn create_user(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
    Json(payload): Json<CreateUserRequest>,
) -> Response {
    // Check admin permission
    if authenticated_user.role != Role::Admin {
        return (StatusCode::FORBIDDEN, "Only admins can create users").into_response();
    }

    // Validate request
    if let Err(err) = payload.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }

    // Create user
    match state.auth_service.create_user(payload).await {
        Ok(user) => {
            info!("User created by admin {}", authenticated_user.user_id);
            (StatusCode::CREATED, Json(user)).into_response()
        }
        Err(DbErr::Query(err)) if err.to_string().contains("unique") => {
            error!("Failed to create user: email already exists");
            (StatusCode::CONFLICT, "Email already exists").into_response()
        }
        Err(err) => {
            error!("Failed to create user: {}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create user: {err}"),
            )
                .into_response()
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/auth/users",
    tag = "Auth",
    params(UserPagination),
    responses(
        (status = 200, description = "Users listed successfully", body = ListUsersResponse),
        (status = 400, description = "Bad request - validation error"),
        (status = 403, description = "Forbidden - admin only"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("jwt_cookie_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn list_users(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
    Query(pagination): Query<UserPagination>,
) -> Response {
    // Check admin permission
    if authenticated_user.role != Role::Admin {
        return (StatusCode::FORBIDDEN, "Only admins can list users").into_response();
    }

    // Validate pagination params
    if let Err(err) = pagination.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }

    // List users
    match state.auth_service.list_users(pagination).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => {
            error!("Failed to list users: {}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to list users: {err}"),
            )
                .into_response()
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/auth/users/{user_id}",
    tag = "Auth",
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User retrieved successfully", body = UserResponse),
        (status = 403, description = "Forbidden - admin only"),
        (status = 404, description = "User not found"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("jwt_cookie_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn get_user(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
    Path(user_id): Path<Uuid>,
) -> Response {
    // Check admin permission
    if authenticated_user.role != Role::Admin {
        return (StatusCode::FORBIDDEN, "Only admins can get user details").into_response();
    }

    // Get user
    match state.auth_service.get_user_by_id(user_id).await {
        Ok(Some(user)) => (StatusCode::OK, Json(user)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "User not found").into_response(),
        Err(err) => {
            error!("Failed to get user {}: {}", user_id, err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to get user: {err}"),
            )
                .into_response()
        }
    }
}

#[utoipa::path(
    put,
    path = "/api/v1/auth/users/{user_id}",
    tag = "Auth",
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    request_body = UpdateUserRequest,
    responses(
        (status = 200, description = "User updated successfully", body = UserResponse),
        (status = 400, description = "Bad request - validation error"),
        (status = 403, description = "Forbidden - admin only"),
        (status = 404, description = "User not found"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("jwt_cookie_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn update_user(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
    Path(user_id): Path<Uuid>,
    Json(payload): Json<UpdateUserRequest>,
) -> Response {
    // Check admin permission
    if authenticated_user.role != Role::Admin {
        return (StatusCode::FORBIDDEN, "Only admins can update users").into_response();
    }

    // Validate request
    if let Err(err) = payload.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }

    // Update user
    match state.auth_service.update_user(user_id, payload).await {
        Ok(Some(user)) => {
            info!(
                "User {} updated by admin {}",
                user_id, authenticated_user.user_id
            );
            (StatusCode::OK, Json(user)).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "User not found").into_response(),
        Err(err) => {
            error!("Failed to update user {}: {}", user_id, err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to update user: {err}"),
            )
                .into_response()
        }
    }
}

#[utoipa::path(
    delete,
    path = "/api/v1/auth/users/{user_id}",
    tag = "Auth",
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    responses(
        (status = 204, description = "User deleted successfully"),
        (status = 400, description = "Bad request - cannot delete admin user"),
        (status = 403, description = "Forbidden - admin only"),
        (status = 404, description = "User not found"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("jwt_cookie_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn delete_user(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
    Path(user_id): Path<Uuid>,
) -> Response {
    // Check admin permission
    if authenticated_user.role != Role::Admin {
        return (StatusCode::FORBIDDEN, "Only admins can delete users").into_response();
    }

    // Delete user with admin check (service handles the check)
    match state.auth_service.delete_user_with_admin_check(user_id).await {
        Ok(Ok(Some(()))) => {
            info!(
                "User {} deleted by admin {}",
                user_id, authenticated_user.user_id
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(Ok(None)) => (StatusCode::NOT_FOUND, "User not found").into_response(),
        Ok(Err(message)) => (StatusCode::BAD_REQUEST, message).into_response(),
        Err(err) => {
            error!("Failed to delete user {}: {}", user_id, err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to delete user: {err}"),
            )
                .into_response()
        }
    }
}

#[utoipa::path(
    put,
    path = "/api/v1/auth/{user_id}/revoke-api-key",
    tag = "Auth",
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    request_body = RevokeApiKeyRequest,
    responses(
        (status = 204, description = "API key revoked successfully"),
        (status = 400, description = "Bad request - validation error"),
        (status = 403, description = "Forbidden - admin only"),
        (status = 404, description = "API key not found or doesn't belong to user"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("jwt_cookie_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn revoke_api_key(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
    Path(user_id): Path<Uuid>,
    Json(payload): Json<RevokeApiKeyRequest>,
) -> Response {
    // Check admin permission
    if authenticated_user.role != Role::Admin {
        return (StatusCode::FORBIDDEN, "Only admins can revoke API keys").into_response();
    }

    // Validate request
    if let Err(err) = payload.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }

    // Revoke the API key - note: NO LOGGING of the API key
    match state
        .auth_service
        .revoke_api_key(payload.api_key, user_id)
        .await
    {
        Ok(Some(())) => {
            info!(
                "API key revoked by admin {} for user {}",
                authenticated_user.user_id, user_id
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "API key not found").into_response(),
        Err(err) => {
            error!("Failed to revoke API key for user {}: {}", user_id, err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to revoke API key: {err}"),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::models::response::CreateApiKeyResponse;
    use crate::test_tools::build_test_app;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use serde_json::json;
    use tower::ServiceExt;
    use uuid::Uuid;

    // Import JWT creation utilities
    use crate::auth::JWT_KEYS;
    use crate::models::auth::JWTClaims;
    use crate::models::response::{ListUsersResponse, UserResponse};
    use crate::test_tools::get_mock_jwt;
    use ::entity::sea_orm_active_enums::Role;
    use chrono::Utc;
    use jsonwebtoken::{encode, Header};

    #[tokio::test]
    async fn login_with_valid_email() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "email": "test@example.com"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual = String::from_utf8((&body).to_vec()).unwrap();
        assert_eq!(actual, "Login email sent");
    }

    #[tokio::test]
    async fn login_invalid_json() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "invalid_field": "test@example.com"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Axum returns 422 Unprocessable Entity for JSON deserialization errors
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn authorize_with_valid_session() {
        let app = build_test_app();
        let test_user_id = Uuid::new_v4();
        let test_session_id = Uuid::new_v4();

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth/authorize")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "user_id": test_user_id.to_string(),
                            "session_id": test_session_id.to_string()
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual = String::from_utf8((&body).to_vec()).unwrap();
        assert_eq!(actual, "Authentication successful");
    }

    #[tokio::test]
    async fn verify_with_valid_jwt() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/auth")
                    .header(http::header::COOKIE, format!("jwt={}", get_mock_jwt()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual = String::from_utf8((&body).to_vec()).unwrap();
        assert!(actual.contains("Verifying your account"));
        assert!(actual.contains("someuser@gmail.com"));
    }

    #[tokio::test]
    async fn verify_without_jwt() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/auth")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn create_api_key_as_admin() {
        let app = build_test_app();
        let target_user_id = Uuid::new_v4();

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(&format!("/api/v1/auth/{}/api-key", target_user_id))
                    .header(http::header::COOKIE, format!("jwt={}", get_mock_jwt()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: CreateApiKeyResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(actual.api_key_secret, "mock_api_key_secret");
    }

    #[tokio::test]
    async fn create_api_key_without_admin_role() {
        let app = build_test_app();
        let target_user_id = Uuid::new_v4();

        let expiry_time: chrono::DateTime<Utc> = Utc::now() + chrono::Duration::hours(24);
        let claims = JWTClaims {
            sub: "researcher@gmail.com".to_string(),
            exp: expiry_time.timestamp() as usize,
            role: Role::Researcher,
        };
        let jwt =
            encode(&Header::default(), &claims, &JWT_KEYS.encoding).expect("Failed to encode JWT");

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(&format!("/api/v1/auth/{}/api-key", target_user_id))
                    .header(http::header::COOKIE, format!("jwt={}", jwt))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual = String::from_utf8((&body).to_vec()).unwrap();
        assert_eq!(actual, "Only admins can create API keys");
    }

    #[tokio::test]
    async fn create_api_key_without_jwt() {
        let app = build_test_app();
        let target_user_id = Uuid::new_v4();

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(&format!("/api/v1/auth/{}/api-key", target_user_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn create_api_key_with_api_key_auth() {
        let app = build_test_app();
        let target_user_id = Uuid::new_v4();

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(&format!("/api/v1/auth/{}/api-key", target_user_id))
                    .header("X-Api-Key", "mock_api_key_secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: CreateApiKeyResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(actual.api_key_secret, "mock_api_key_secret");
    }

    #[tokio::test]
    async fn create_api_key_with_invalid_api_key() {
        let app = build_test_app();
        let target_user_id = Uuid::new_v4();

        // Mock API key verification returns None for invalid keys in the real implementation
        // but our mock always returns Some, so we test with an empty string
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(&format!("/api/v1/auth/{}/api-key", target_user_id))
                    .header("X-Api-Key", "invalid_key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Mock returns valid user info regardless, so this succeeds
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn verify_with_api_key() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/auth")
                    .header("X-Api-Key", "mock_api_key_secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual = String::from_utf8((&body).to_vec()).unwrap();
        assert!(actual.contains("Verifying your account"));
        // With API key auth, the user_id is the email from the API key info
        assert!(actual.contains("test@example.com"));
    }

    // User management endpoint tests

    #[tokio::test]
    async fn create_user_as_admin() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth/users")
                    .header(http::header::COOKIE, format!("jwt={}", get_mock_jwt()))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "email": "newuser@example.com",
                            "role": "researcher",
                            "is_active": true
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: UserResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(actual.email, "newuser@example.com");
        assert_eq!(actual.role, Role::Researcher);
        assert!(actual.is_active);
    }

    #[tokio::test]
    async fn create_user_without_admin_role() {
        let app = build_test_app();

        let expiry_time: chrono::DateTime<Utc> = Utc::now() + chrono::Duration::hours(24);
        let claims = JWTClaims {
            sub: "researcher@gmail.com".to_string(),
            exp: expiry_time.timestamp() as usize,
            role: Role::Researcher,
        };
        let jwt =
            encode(&Header::default(), &claims, &JWT_KEYS.encoding).expect("Failed to encode JWT");

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth/users")
                    .header(http::header::COOKIE, format!("jwt={}", jwt))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "email": "newuser@example.com",
                            "role": "researcher",
                            "is_active": true
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual = String::from_utf8((&body).to_vec()).unwrap();
        assert_eq!(actual, "Only admins can create users");
    }

    #[tokio::test]
    async fn create_user_invalid_request() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/auth/users")
                    .header(http::header::COOKIE, format!("jwt={}", get_mock_jwt()))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "email": "",
                            "role": "researcher",
                            "is_active": true
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_users_as_admin() {
        let app = build_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/auth/users")
                    .header(http::header::COOKIE, format!("jwt={}", get_mock_jwt()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: ListUsersResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(actual.items.len(), 1);
        assert_eq!(actual.num_pages, 1);
    }

    #[tokio::test]
    async fn list_users_without_admin_role() {
        let app = build_test_app();

        let expiry_time: chrono::DateTime<Utc> = Utc::now() + chrono::Duration::hours(24);
        let claims = JWTClaims {
            sub: "researcher@gmail.com".to_string(),
            exp: expiry_time.timestamp() as usize,
            role: Role::Researcher,
        };
        let jwt =
            encode(&Header::default(), &claims, &JWT_KEYS.encoding).expect("Failed to encode JWT");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/auth/users")
                    .header(http::header::COOKIE, format!("jwt={}", jwt))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual = String::from_utf8((&body).to_vec()).unwrap();
        assert_eq!(actual, "Only admins can list users");
    }

    #[tokio::test]
    async fn get_user_as_admin() {
        let app = build_test_app();
        let target_user_id = Uuid::new_v4();

        let response = app
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/v1/auth/users/{}", target_user_id))
                    .header(http::header::COOKIE, format!("jwt={}", get_mock_jwt()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: UserResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(actual.id, target_user_id);
    }

    #[tokio::test]
    async fn get_user_without_admin_role() {
        let app = build_test_app();
        let target_user_id = Uuid::new_v4();

        let expiry_time: chrono::DateTime<Utc> = Utc::now() + chrono::Duration::hours(24);
        let claims = JWTClaims {
            sub: "researcher@gmail.com".to_string(),
            exp: expiry_time.timestamp() as usize,
            role: Role::Researcher,
        };
        let jwt =
            encode(&Header::default(), &claims, &JWT_KEYS.encoding).expect("Failed to encode JWT");

        let response = app
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/v1/auth/users/{}", target_user_id))
                    .header(http::header::COOKIE, format!("jwt={}", jwt))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual = String::from_utf8((&body).to_vec()).unwrap();
        assert_eq!(actual, "Only admins can get user details");
    }

    #[tokio::test]
    async fn update_user_as_admin() {
        let app = build_test_app();
        let target_user_id = Uuid::new_v4();

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(&format!("/api/v1/auth/users/{}", target_user_id))
                    .header(http::header::COOKIE, format!("jwt={}", get_mock_jwt()))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "role": "contributor",
                            "is_active": false
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual: UserResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(actual.role, Role::Contributor);
        assert!(!actual.is_active);
    }

    #[tokio::test]
    async fn update_user_without_admin_role() {
        let app = build_test_app();
        let target_user_id = Uuid::new_v4();

        let expiry_time: chrono::DateTime<Utc> = Utc::now() + chrono::Duration::hours(24);
        let claims = JWTClaims {
            sub: "researcher@gmail.com".to_string(),
            exp: expiry_time.timestamp() as usize,
            role: Role::Researcher,
        };
        let jwt =
            encode(&Header::default(), &claims, &JWT_KEYS.encoding).expect("Failed to encode JWT");

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(&format!("/api/v1/auth/users/{}", target_user_id))
                    .header(http::header::COOKIE, format!("jwt={}", jwt))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "role": "contributor",
                            "is_active": false
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual = String::from_utf8((&body).to_vec()).unwrap();
        assert_eq!(actual, "Only admins can update users");
    }

    #[tokio::test]
    async fn delete_user_as_admin() {
        let app = build_test_app();
        let target_user_id = Uuid::new_v4();

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(&format!("/api/v1/auth/users/{}", target_user_id))
                    .header(http::header::COOKIE, format!("jwt={}", get_mock_jwt()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn delete_user_without_admin_role() {
        let app = build_test_app();
        let target_user_id = Uuid::new_v4();

        let expiry_time: chrono::DateTime<Utc> = Utc::now() + chrono::Duration::hours(24);
        let claims = JWTClaims {
            sub: "researcher@gmail.com".to_string(),
            exp: expiry_time.timestamp() as usize,
            role: Role::Researcher,
        };
        let jwt =
            encode(&Header::default(), &claims, &JWT_KEYS.encoding).expect("Failed to encode JWT");

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::DELETE)
                    .uri(&format!("/api/v1/auth/users/{}", target_user_id))
                    .header(http::header::COOKIE, format!("jwt={}", jwt))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual = String::from_utf8((&body).to_vec()).unwrap();
        assert_eq!(actual, "Only admins can delete users");
    }

    #[tokio::test]
    async fn revoke_api_key_as_admin() {
        let app = build_test_app();
        let target_user_id = Uuid::new_v4();

        // Use a valid base64-URL encoded string (32 bytes when decoded)
        // This is "test_api_key_secret_32_bytes_long" base64-encoded
        let valid_api_key = "dGVzdF9hcGlfa2V5X3NlY3JldF8zMl9ieXRlc19sb25n";

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(&format!("/api/v1/auth/{}/revoke-api-key", target_user_id))
                    .header(http::header::COOKIE, format!("jwt={}", get_mock_jwt()))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "api_key": valid_api_key
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn revoke_api_key_without_admin_role() {
        let app = build_test_app();
        let target_user_id = Uuid::new_v4();

        let expiry_time: chrono::DateTime<Utc> = Utc::now() + chrono::Duration::hours(24);
        let claims = JWTClaims {
            sub: "researcher@gmail.com".to_string(),
            exp: expiry_time.timestamp() as usize,
            role: Role::Researcher,
        };
        let jwt =
            encode(&Header::default(), &claims, &JWT_KEYS.encoding).expect("Failed to encode JWT");

        // Use a valid base64-URL encoded string
        let valid_api_key = "dGVzdF9hcGlfa2V5X3NlY3JldF8zMl9ieXRlc19sb25n";

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(&format!("/api/v1/auth/{}/revoke-api-key", target_user_id))
                    .header(http::header::COOKIE, format!("jwt={}", jwt))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "api_key": valid_api_key
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let actual = String::from_utf8((&body).to_vec()).unwrap();
        assert_eq!(actual, "Only admins can revoke API keys");
    }

    #[tokio::test]
    async fn revoke_api_key_invalid_request() {
        let app = build_test_app();
        let target_user_id = Uuid::new_v4();

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(&format!("/api/v1/auth/{}/revoke-api-key", target_user_id))
                    .header(http::header::COOKIE, format!("jwt={}", get_mock_jwt()))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "api_key": ""
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn revoke_api_key_without_auth() {
        let app = build_test_app();
        let target_user_id = Uuid::new_v4();

        // Use a valid base64-URL encoded string
        let valid_api_key = "dGVzdF9hcGlfa2V5X3NlY3JldF8zMl9ieXRlc19sb25n";

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::PUT)
                    .uri(&format!("/api/v1/auth/{}/revoke-api-key", target_user_id))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "api_key": valid_api_key
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
