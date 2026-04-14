use chrono::Utc;
use kube::Client;

use crate::{build_checks, config::AuditConfig, models::AuditReport};

pub async fn run_audit(config: AuditConfig) -> anyhow::Result<AuditReport> {
    let client = Client::try_default().await?;
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
