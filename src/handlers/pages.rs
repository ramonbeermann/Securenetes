use askama::Template;
use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;

use crate::{
    services::app_state::{SharedState, UiSettings},
    templates::{
        fmt_date, severity_class, severity_label, ClustersTemplate, DashboardMetric,
        DashboardTemplate, FindingDetailTemplate, FindingsTemplate, ReportsTemplate, ScansTemplate,
        SettingsTemplate, SetupTemplate,
    },
};

fn setup_redirect_if_missing(has_config: bool) -> Option<Redirect> {
    if has_config {
        None
    } else {
        Some(Redirect::to("/setup"))
    }
}

pub async fn dashboard(State(state): State<SharedState>) -> Result<Response, AppError> {
    let data = state.read().await;
    if let Some(redirect) = setup_redirect_if_missing(data.kube_config.is_some()) {
        return Ok(redirect.into_response());
    }

    let report = data.latest_report.clone();

    let findings = report
        .as_ref()
        .map(|r| r.all_findings().cloned().collect::<Vec<_>>())
        .unwrap_or_default();

    let metrics = vec![
        DashboardMetric {
            label: "Critical",
            value: findings
                .iter()
                .filter(|f| severity_label(&f.severity) == "Critical")
                .count(),
        },
        DashboardMetric {
            label: "High",
            value: findings
                .iter()
                .filter(|f| severity_label(&f.severity) == "High")
                .count(),
        },
        DashboardMetric {
            label: "Medium",
            value: findings
                .iter()
                .filter(|f| severity_label(&f.severity) == "Medium")
                .count(),
        },
        DashboardMetric {
            label: "Low/Info",
            value: findings
                .iter()
                .filter(|f| {
                    let cls = severity_class(&f.severity);
                    cls == "low" || cls == "info"
                })
                .count(),
        },
    ];

    let top_risks = findings.into_iter().take(6).collect();
    let recent_scans = data.scans.iter().rev().take(6).cloned().collect();

    Ok(Html(
        DashboardTemplate {
            page_title: "Dashboard",
            report,
            metrics,
            top_risks,
            recent_scans,
        }
        .render()?,
    )
    .into_response())
}

pub async fn scans(State(state): State<SharedState>) -> Result<Response, AppError> {
    let data = state.read().await;
    if let Some(redirect) = setup_redirect_if_missing(data.kube_config.is_some()) {
        return Ok(redirect.into_response());
    }

    Ok(Html(
        ScansTemplate {
            page_title: "Scans",
            scans: data.scans.iter().rev().cloned().collect(),
        }
        .render()?,
    )
    .into_response())
}

pub async fn findings(State(state): State<SharedState>) -> Result<Response, AppError> {
    let data = state.read().await;
    if let Some(redirect) = setup_redirect_if_missing(data.kube_config.is_some()) {
        return Ok(redirect.into_response());
    }

    let findings = data
        .latest_report
        .as_ref()
        .map(|r| r.all_findings().cloned().collect())
        .unwrap_or_default();

    Ok(Html(
        FindingsTemplate {
            page_title: "Findings",
            findings,
        }
        .render()?,
    )
    .into_response())
}

pub async fn finding_detail(
    Path(id): Path<String>,
    State(state): State<SharedState>,
) -> Result<Response, AppError> {
    let data = state.read().await;
    if let Some(redirect) = setup_redirect_if_missing(data.kube_config.is_some()) {
        return Ok(redirect.into_response());
    }

    let finding = data
        .latest_report
        .as_ref()
        .and_then(|r| r.all_findings().find(|f| f.id == id).cloned())
        .ok_or_else(|| AppError::Status(StatusCode::NOT_FOUND, "Finding not found".into()))?;

    Ok(Html(
        FindingDetailTemplate {
            page_title: "Finding Detail",
            finding,
        }
        .render()?,
    )
    .into_response())
}

pub async fn reports(State(state): State<SharedState>) -> Result<Response, AppError> {
    let data = state.read().await;
    if let Some(redirect) = setup_redirect_if_missing(data.kube_config.is_some()) {
        return Ok(redirect.into_response());
    }

    Ok(Html(
        ReportsTemplate {
            page_title: "Reports",
            reports: data.report_history.iter().rev().cloned().collect(),
        }
        .render()?,
    )
    .into_response())
}

pub async fn clusters(State(state): State<SharedState>) -> Result<Response, AppError> {
    let data = state.read().await;
    if let Some(redirect) = setup_redirect_if_missing(data.kube_config.is_some()) {
        return Ok(redirect.into_response());
    }

    Ok(Html(
        ClustersTemplate {
            page_title: "Clusters",
            clusters: data.clusters.clone(),
        }
        .render()?,
    )
    .into_response())
}

pub async fn settings(State(state): State<SharedState>) -> Result<Response, AppError> {
    let data = state.read().await;
    if let Some(redirect) = setup_redirect_if_missing(data.kube_config.is_some()) {
        return Ok(redirect.into_response());
    }

    Ok(Html(
        SettingsTemplate {
            page_title: "Settings",
            settings: data.settings.clone(),
        }
        .render()?,
    )
    .into_response())
}

pub async fn setup(State(state): State<SharedState>) -> Result<Html<String>, AppError> {
    let data = state.read().await;
    let existing = data.kube_config.clone();

    Ok(Html(
        SetupTemplate {
            page_title: "Kubernetes Setup",
            existing,
        }
        .render()?,
    ))
}

#[derive(Debug, Deserialize)]
pub struct SettingsForm {
    report_title: String,
    output_format: String,
    branding: String,
}

pub async fn save_settings(
    State(state): State<SharedState>,
    Form(payload): Form<SettingsForm>,
) -> Result<Response, AppError> {
    let mut data = state.write().await;
    data.settings = UiSettings {
        report_title: payload.report_title,
        output_format: payload.output_format,
        branding: payload.branding,
    };

    Ok((StatusCode::SEE_OTHER, [(header::LOCATION, "/settings")], "").into_response())
}

#[derive(Debug)]
pub enum AppError {
    Template(askama::Error),
    Status(StatusCode, String),
}

impl From<askama::Error> for AppError {
    fn from(value: askama::Error) -> Self {
        Self::Template(value)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::Template(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Template rendering error: {err}"),
            )
                .into_response(),
            AppError::Status(status, message) => (status, message).into_response(),
        }
    }
}

#[allow(dead_code)]
fn _fmt_date_for_templates(v: &Option<chrono::DateTime<chrono::Utc>>) -> String {
    fmt_date(v)
}
