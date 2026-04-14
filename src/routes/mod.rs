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
        .route("/api/scans", get(api::list_scans))
        .route("/api/scans/start", post(api::start_scan))
        .route("/api/findings", get(api::list_findings))
        .with_state(state)
}
