use async_trait::async_trait;
use kube::Client;

use crate::{
    checks::Check,
    config::AuditConfig,
    models::{CheckResult, Evidence, Finding, Severity},
};

pub struct EtcdCheck;

#[async_trait]
impl Check for EtcdCheck {
    fn name(&self) -> &'static str {
        "etcd"
    }

    async fn run(&self, _client: &Client, _config: &AuditConfig) -> anyhow::Result<CheckResult> {
        Ok(CheckResult {
            check_name: self.name().into(),
            findings: vec![Finding {
                id: "ETCD-EXPOSURE-HEURISTIC".to_string(),
                title: "etcd-Absicherung muss separat validiert werden".to_string(),
                area: "etcd".to_string(),
                criterion: "Verschlüsselung-at-Rest und Netzwerkexposition".to_string(),
                description:
                    "Aus Workload-Sicht kann etcd-Zugriff/Verschlüsselung nicht abschließend belegt werden."
                        .to_string(),
                resource: None,
                evidence: Evidence {
                    summary: "Heuristische Feststellung".to_string(),
                    details: vec![
                        "Prüfen: --encryption-provider-config, TLS-Clientauth, Port-Exposition"
                            .to_string(),
                    ],
                },
                risk: "Kompromittierung von Secrets/Clusterstate bei schwacher etcd-Security".to_string(),
                recommendation: "etcd isolieren, TLS mTLS erzwingen, Encryption-at-Rest aktivieren.".to_string(),
                severity: Severity::High,
                heuristic: true,
            }],
        })
    }
}
