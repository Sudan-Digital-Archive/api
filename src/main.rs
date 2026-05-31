mod app_factory;
mod auth;
mod config;
mod mocks;
mod models;
mod open_api_spec;
mod repos;
mod routes;
mod services;

use crate::app_factory::{build_app, create_app};
use crate::config::build_app_config;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::info;

#[tokio::main]
async fn main() {
    let app_config = build_app_config();
    let (app_state, final_config) = build_app(&app_config).await.expect("Failed to build app");
    let app = create_app(app_state, final_config);

    let addr: SocketAddr = app_config
        .listener_address
        .parse()
        .expect("Should be in address format like 0.0.0.0:5000");

    info!("listening on {}", addr);
    let listener = TcpListener::bind(addr).await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
