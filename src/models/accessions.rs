use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::fmt;

#[derive(Debug)]
pub enum AccessionError {
    ClientError(String),
    DatabaseError(String),
}

impl fmt::Display for AccessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccessionError::ClientError(msg) => write!(f, "{}", msg),
            AccessionError::DatabaseError(msg) => write!(f, "{}", msg),
        }
    }
}

impl IntoResponse for AccessionError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            AccessionError::ClientError(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AccessionError::DatabaseError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}
