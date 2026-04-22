use std::{collections::BTreeMap, sync::Arc};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::RwLock;

use crate::{config::AuditConfig, models::AuditReport, services::kube_ui::KubeUiConfig};

#[derive(Debug, Clone, Serialize)]
pub struct ScanJob {
    pub id: String,
    pub status: String,
    pub progress: u8,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClusterInfo {
    pub name: String,
    pub status: String,
    pub last_scan: Option<DateTime<Utc>>,
    pub risk: String,
    pub reachable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct UiSettings {
    pub report_title: String,
    pub output_format: String,
    pub branding: String,
}

#[derive(Debug)]
pub struct AppData {
    pub latest_report: Option<AuditReport>,
    pub report_history: Vec<AuditReport>,
    pub scans: Vec<ScanJob>,
    pub clusters: Vec<ClusterInfo>,
    pub settings: UiSettings,
    pub config: AuditConfig,
    pub kube_config: Option<KubeUiConfig>,
    pub scan_errors: BTreeMap<String, String>,
}

impl AppData {
    pub fn new(
        config: AuditConfig,
        seed_report: Option<AuditReport>,
        kube_config: Option<KubeUiConfig>,
    ) -> Self {
        let report_history = seed_report.clone().map(|r| vec![r]).unwrap_or_default();
        let latest_report = seed_report;

        Self {
            latest_report,
            report_history,
            scans: Vec::new(),
            clusters: vec![ClusterInfo {
                name: config.cluster_name.clone(),
                status: "Healthy".into(),
                last_scan: None,
                risk: "Unknown".into(),
                reachable: true,
            }],
            settings: UiSettings {
                report_title: "Securenetes Compliance Report".into(),
                output_format: "html".into(),
                branding: "Securenetes".into(),
            },
            config,
            kube_config,
            scan_errors: BTreeMap::new(),
        }
    }
}

pub type SharedState = Arc<RwLock<AppData>>;
