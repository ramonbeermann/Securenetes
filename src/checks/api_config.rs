use async_trait::async_trait;
use kube::Client;

use crate::{
    checks::Check,
    config::AuditConfig,
    models::{CheckResult, Evidence, Finding, Severity},
};

pub struct ApiServerConfigCheck;

#[async_trait]
impl Check for ApiServerConfigCheck {
    fn name(&self) -> &'static str {
        "api_server_config"
    }

    async fn run(&self, _client: &Client, _config: &AuditConfig) -> anyhow::Result<CheckResult> {
        Ok(CheckResult {
            check_name: self.name().into(),
            findings: vec![Finding {
                id: "APISERVER-HARDENING-HEURISTIC".to_string(),
                title: "API-Server Hardening nur teilautomatisiert bewertet".to_string(),
                area: "API Server / Cluster-Konfiguration".to_string(),
                criterion: "Sichere Flags und AuthN/AuthZ-Konfiguration".to_string(),
                description: "Direkte API-Server-Flags sind in gemanagten Clustern oft nicht vollständig auslesbar.".to_string(),
                resource: None,
                evidence: Evidence {
                    summary: "Automatisierte Vollprüfung nicht in allen Umgebungen möglich".to_string(),
                    details: vec![
                        "Manuelle Ergänzung: kube-apiserver Flags, Audit Policy, Admission Controller Status"
                            .to_string(),
                    ],
                },
                risk: "Hardening-Lücken könnten unentdeckt bleiben".to_string(),
                recommendation: "Cluster-Benchmark (z.B. CIS) und Control-Plane-Review ergänzen.".to_string(),
                severity: Severity::Info,
                heuristic: true,
            }],
        })
    }
}
