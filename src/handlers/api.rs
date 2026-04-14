use axum::{extract::State, Json};
use chrono::Utc;
use serde::Serialize;
use tokio::task;

use crate::services::{
    app_state::{ScanJob, SharedState},
    audit_runner::run_audit,
};

#[derive(Debug, Serialize)]
pub struct ApiStatus {
    pub ok: bool,
    pub message: String,
    pub scan_id: Option<String>,
}

pub async fn list_scans(State(state): State<SharedState>) -> Json<Vec<ScanJob>> {
    let data = state.read().await;
    Json(data.scans.clone())
}

pub async fn list_findings(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let data = state.read().await;
    let findings = data
        .latest_report
        .as_ref()
        .map(|r| r.all_findings().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    Json(serde_json::json!({ "items": findings, "total": findings.len() }))
}

pub async fn start_scan(State(state): State<SharedState>) -> Json<ApiStatus> {
    let scan_id = format!("scan-{}", Utc::now().timestamp_millis());
    {
        let mut data = state.write().await;
        data.scans.push(ScanJob {
            id: scan_id.clone(),
            status: "running".into(),
            progress: 10,
            started_at: Utc::now(),
            finished_at: None,
            message: "Scan initialized".into(),
        });
    }

    let state_clone = state.clone();
    let scan_id_clone = scan_id.clone();
    task::spawn(async move {
        let config = {
            let data = state_clone.read().await;
            data.config.clone()
        };

        match run_audit(config).await {
            Ok(report) => {
                let mut data = state_clone.write().await;
                if let Some(scan) = data.scans.iter_mut().find(|s| s.id == scan_id_clone) {
                    scan.status = "completed".into();
                    scan.progress = 100;
                    scan.finished_at = Some(Utc::now());
                    scan.message = "Audit finished".into();
                }
                if let Some(cluster) = data.clusters.first_mut() {
                    cluster.last_scan = Some(Utc::now());
                    cluster.risk = report
                        .all_findings()
                        .next()
                        .map(|f| format!("{} findings", report.all_findings().count()))
                        .unwrap_or_else(|| "No findings".into());
                }
                data.latest_report = Some(report.clone());
                data.report_history.push(report);
            }
            Err(err) => {
                let mut data = state_clone.write().await;
                if let Some(scan) = data.scans.iter_mut().find(|s| s.id == scan_id_clone) {
                    scan.status = "failed".into();
                    scan.progress = 100;
                    scan.finished_at = Some(Utc::now());
                    scan.message = format!("Scan failed: {err}");
                }
                data.scan_errors.insert(scan_id_clone, err.to_string());
            }
        }
    });

    Json(ApiStatus {
        ok: true,
        message: "Scan started".into(),
        scan_id: Some(scan_id),
    })
}
