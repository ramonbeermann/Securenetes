use crate::models::AuditReport;

pub fn render(report: &AuditReport) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}
