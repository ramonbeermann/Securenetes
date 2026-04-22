use axum::{
    routing::{get, post},
    Router,
};

use crate::{
    handlers::{api, pages},
    services::app_state::SharedState,
};

pub fn app_router(state: SharedState) -> Router {
    Router::new()
        .route("/", get(pages::dashboard))
        .route("/scans", get(pages::scans))
        .route("/findings", get(pages::findings))
        .route("/findings/:id", get(pages::finding_detail))
        .route("/reports", get(pages::reports))
        .route("/clusters", get(pages::clusters))
        .route("/settings", get(pages::settings).post(pages::save_settings))
        .route("/setup", get(pages::setup))
        .route("/api/scans", get(api::list_scans))
        .route("/api/scans/start", post(api::start_scan))
        .route("/api/findings", get(api::list_findings))
        .route("/api/kube/test", post(api::test_kube_connection))
        .route("/api/kube/save", post(api::save_kube_connection))
        .with_state(state)
}
