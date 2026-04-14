use async_trait::async_trait;
use k8s_openapi::api::core::v1::Secret;
use kube::{api::ListParams, Api, Client};

use crate::{
    checks::Check,
    config::AuditConfig,
    models::{CheckResult, Evidence, Finding, ResourceReference, Severity},
};

pub struct SecretsCheck;

#[async_trait]
impl Check for SecretsCheck {
    fn name(&self) -> &'static str {
        "secrets"
    }

    async fn run(&self, client: &Client, _config: &AuditConfig) -> anyhow::Result<CheckResult> {
        let api: Api<Secret> = Api::all(client.clone());
        let mut findings = Vec::new();

        for secret in api.list(&ListParams::default()).await? {
            let name = secret.metadata.name.clone().unwrap_or_default();
            let ns = secret.metadata.namespace.clone();

            let sensitive_name = ["password", "token", "key", "secret"]
                .iter()
                .any(|needle| name.to_lowercase().contains(needle));

            if sensitive_name && secret.type_.as_deref() == Some("Opaque") {
                findings.push(Finding {
                    id: format!("SECRET-SENSITIVE-{}", name),
                    title: "Potenziell sensibles Secret identifiziert".to_string(),
                    area: "Secrets".to_string(),
                    criterion: "Sensiblen Datenbestand minimieren und absichern".to_string(),
                    description: "Name deutet auf sensible Inhalte hin; Speicherung als Opaque Secret.".to_string(),
                    resource: Some(ResourceReference {
                        kind: "Secret".to_string(),
                        namespace: ns,
                        name,
                    }),
                    evidence: Evidence {
                        summary: "Heuristik auf Basis Secret-Namen".to_string(),
                        details: vec!["Namensmuster: password/token/key/secret".to_string()],
                    },
                    risk: "Unzureichend abgesicherte Geheimnisse können kompromittiert werden.".to_string(),
                    recommendation:
                        "KMS-Integration/External Secrets nutzen, Zugriffe via RBAC strikt einschränken."
                            .to_string(),
                    severity: Severity::Medium,
                    heuristic: true,
                });
            }
        }

        Ok(CheckResult {
            check_name: self.name().into(),
            findings,
        })
    }
}
