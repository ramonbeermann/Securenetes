use chrono::Utc;
use kube::Client;

use crate::{
    build_checks,
    config::AuditConfig,
    models::AuditReport,
    services::kube_ui::{build_config_from_ui, KubeUiConfig},
};

pub async fn run_audit(
    config: AuditConfig,
    kube_ui_config: KubeUiConfig,
) -> anyhow::Result<AuditReport> {
    let kube_config = build_config_from_ui(kube_ui_config).await?;
    let client = Client::try_from(kube_config)?;
    let checks = build_checks(&config);
    let mut results = Vec::new();

    for check in checks {
        results.push(check.run(&client, &config).await?);
    }

    Ok(AuditReport {
        report_id: format!("SNET-{}", Utc::now().format("%Y%m%d%H%M%S")),
        profile: config.profile_name,
        generated_at: Utc::now(),
        target: config.cluster_name,
        results,
    })
}
