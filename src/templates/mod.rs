use askama::Template;
use chrono::{DateTime, Utc};

use crate::models::{AuditReport, Finding, Severity};
use crate::services::app_state::{ClusterInfo, ScanJob, UiSettings};

#[derive(Debug, Clone)]
pub struct DashboardMetric {
    pub label: &'static str,
    pub value: usize,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub page_title: &'static str,
    pub report: Option<AuditReport>,
    pub metrics: Vec<DashboardMetric>,
    pub top_risks: Vec<Finding>,
    pub recent_scans: Vec<ScanJob>,
}

#[derive(Template)]
#[template(path = "scans.html")]
pub struct ScansTemplate {
    pub page_title: &'static str,
    pub scans: Vec<ScanJob>,
}

#[derive(Template)]
#[template(path = "findings.html")]
pub struct FindingsTemplate {
    pub page_title: &'static str,
    pub findings: Vec<Finding>,
}

#[derive(Template)]
#[template(path = "finding_detail.html")]
pub struct FindingDetailTemplate {
    pub page_title: &'static str,
    pub finding: Finding,
}

#[derive(Template)]
#[template(path = "reports.html")]
pub struct ReportsTemplate {
    pub page_title: &'static str,
    pub reports: Vec<AuditReport>,
}

#[derive(Template)]
#[template(path = "clusters.html")]
pub struct ClustersTemplate {
    pub page_title: &'static str,
    pub clusters: Vec<ClusterInfo>,
}

#[derive(Template)]
#[template(path = "settings.html")]
pub struct SettingsTemplate {
    pub page_title: &'static str,
    pub settings: UiSettings,
}

pub fn severity_label(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

pub fn severity_class(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

pub fn fmt_date(v: &Option<DateTime<Utc>>) -> String {
    v.map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| "-".into())
}
