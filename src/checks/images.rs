use async_trait::async_trait;
use k8s_openapi::api::core::v1::Pod;
use kube::{api::ListParams, Api, Client};

use crate::{
    checks::Check,
    config::AuditConfig,
    models::{CheckResult, Evidence, Finding, ResourceReference, Severity},
};

pub struct ImagesCheck;

#[async_trait]
impl Check for ImagesCheck {
    fn name(&self) -> &'static str {
        "images"
    }

    async fn run(&self, client: &Client, _config: &AuditConfig) -> anyhow::Result<CheckResult> {
        let api: Api<Pod> = Api::all(client.clone());
        let mut findings = Vec::new();

        for pod in api.list(&ListParams::default()).await? {
            if let Some(spec) = pod.spec.as_ref() {
                for c in &spec.containers {
                    let image = c.image.clone().unwrap_or_default();
                    if image.ends_with(":latest") || !image.contains(':') {
                        findings.push(Finding {
                            id: format!(
                                "IMG-UNPINNED-{}-{}",
                                pod.metadata.namespace.clone().unwrap_or_default(),
                                pod.metadata.name.clone().unwrap_or_default()
                            ),
                            title: "Ungepinnte oder latest Image-Tags".to_string(),
                            area: "Images".to_string(),
                            criterion: "Deterministische und überprüfbare Image-Versionierung"
                                .to_string(),
                            description: format!(
                                "Container {} nutzt potenziell unsicheren Tag: {image}",
                                c.name
                            ),
                            resource: Some(ResourceReference {
                                kind: "Pod".to_string(),
                                namespace: pod.metadata.namespace.clone(),
                                name: pod.metadata.name.clone().unwrap_or_default(),
                            }),
                            evidence: Evidence {
                                summary: format!("image={image}"),
                                details: vec!["Kein digest pinning".to_string()],
                            },
                            risk: "Nicht reproduzierbare Deployments und Supply-Chain-Risiken"
                                .to_string(),
                            recommendation:
                                "Image per SHA256-Digest pinnen und Admission Policies ergänzen."
                                    .to_string(),
                            severity: Severity::Medium,
                            heuristic: false,
                        });
                    }
                }
            }
        }

        Ok(CheckResult {
            check_name: self.name().into(),
            findings,
        })
    }
}
