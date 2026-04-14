use async_trait::async_trait;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::{api::ListParams, Api, Client};

use crate::{
    checks::Check,
    config::AuditConfig,
    models::{CheckResult, Evidence, Finding, Severity},
};

pub struct LoggingMonitoringCheck;

#[async_trait]
impl Check for LoggingMonitoringCheck {
    fn name(&self) -> &'static str {
        "logging_monitoring"
    }

    async fn run(&self, client: &Client, _config: &AuditConfig) -> anyhow::Result<CheckResult> {
        let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), "kube-system");
        let cms = cm_api.list(&ListParams::default()).await?;

        let mut findings = Vec::new();
        let has_known_log_agents = cms.iter().any(|cm| {
            cm.metadata
                .name
                .as_deref()
                .map(|n| n.contains("fluent") || n.contains("loki") || n.contains("audit"))
                .unwrap_or(false)
        });

        if !has_known_log_agents {
            findings.push(Finding {
                id: "LOG-NO-CENTRAL-AGENT".to_string(),
                title: "Zentralisierte Logs nicht eindeutig nachweisbar".to_string(),
                area: "Logging / Monitoring".to_string(),
                criterion: "Auditierbarkeit von sicherheitsrelevanten Ereignissen".to_string(),
                description: "Es wurden keine typischen Logging-Konfigurationsartefakte in kube-system erkannt.".to_string(),
                resource: None,
                evidence: Evidence {
                    summary: "Heuristik auf ConfigMap-Namen".to_string(),
                    details: vec!["Kein Hinweis auf fluent/loki/audit".to_string()],
                },
                risk: "Sicherheitsvorfälle könnten unvollständig nachvollziehbar sein".to_string(),
                recommendation: "Zentrales, manipulationssicheres Logging inkl. Retention und Alarmierung etablieren."
                    .to_string(),
                severity: Severity::Medium,
                heuristic: true,
            });
        }

        Ok(CheckResult {
            check_name: self.name().into(),
            findings,
        })
    }
}
