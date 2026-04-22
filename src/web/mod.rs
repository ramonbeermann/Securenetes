use std::{fs, net::SocketAddr, path::Path};

use anyhow::Context;
use axum::Router;
use tokio::sync::RwLock;
use tower_http::services::ServeDir;
use tracing::info;

use crate::{
    config::AuditConfig,
    models::AuditReport,
    routes::app_router,
    services::{
        app_state::{AppData, SharedState},
        kube_ui::load_kube_ui_config,
    },
};

pub async fn start_server(bind: SocketAddr, config: AuditConfig) -> anyhow::Result<()> {
    let seed_report = load_seed_report("examples/sample_report.json").ok();
    let kube_config = load_kube_ui_config()?;
    let state: SharedState =
        std::sync::Arc::new(RwLock::new(AppData::new(config, seed_report, kube_config)));

    let app = Router::new()
        .nest("", app_router(state))
        .nest_service("/static", ServeDir::new("static"));

    info!("Securenetes UI listening on http://{}", bind);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn load_seed_report(path: impl AsRef<Path>) -> anyhow::Result<AuditReport> {
    let raw = fs::read_to_string(path.as_ref())
        .with_context(|| format!("could not read seed report: {}", path.as_ref().display()))?;
    let report: AuditReport = serde_json::from_str(&raw)?;
    Ok(report)
}
