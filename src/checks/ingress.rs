use async_trait::async_trait;
use k8s_openapi::api::{core::v1::Service, networking::v1::Ingress};
use kube::{api::ListParams, Api, Client};

use crate::{
    checks::Check,
    config::AuditConfig,
    models::{CheckResult, Evidence, Finding, ResourceReference, Severity},
};

pub struct IngressExposureCheck;

#[async_trait]
impl Check for IngressExposureCheck {
    fn name(&self) -> &'static str {
        "ingress"
    }

    async fn run(&self, client: &Client, _config: &AuditConfig) -> anyhow::Result<CheckResult> {
        let svc_api: Api<Service> = Api::all(client.clone());
        let ing_api: Api<Ingress> = Api::all(client.clone());
        let mut findings = Vec::new();

        for svc in svc_api.list(&ListParams::default()).await? {
            if let Some(spec) = svc.spec {
                if let Some(ty) = spec.type_ {
                    if ty == "LoadBalancer" || ty == "NodePort" {
                        let name = svc.metadata.name.clone().unwrap_or_default();
                        findings.push(Finding {
                            id: format!("EXPOSURE-SVC-{name}"),
                            title: format!("Service mit externer Exposition ({ty})"),
                            area: "Ingress / Exposure".to_string(),
                            criterion: "Exposition nur nach minimalem Need-to-expose".to_string(),
                            description: "Service ist potenziell öffentlich erreichbar."
                                .to_string(),
                            resource: Some(ResourceReference {
                                kind: "Service".to_string(),
                                namespace: svc.metadata.namespace.clone(),
                                name,
                            }),
                            evidence: Evidence {
                                summary: format!("spec.type={ty}"),
                                details: vec!["Externe Angriffsfläche vorhanden".to_string()],
                            },
                            risk: "Direkte Angriffsfläche auf Workloads".to_string(),
                            recommendation:
                                "Ingress Controller mit WAF/TLS, SourceRanges und AuthN einsetzen."
                                    .to_string(),
                            severity: Severity::High,
                            heuristic: false,
                        });
                    }
                }
            }
        }

        for ing in ing_api.list(&ListParams::default()).await? {
            let name = ing.metadata.name.clone().unwrap_or_default();
            let tls_missing = ing.spec.as_ref().and_then(|s| s.tls.as_ref()).is_none();
            if tls_missing {
                findings.push(Finding {
                    id: format!("EXPOSURE-ING-NOTLS-{name}"),
                    title: "Ingress ohne TLS-Block".to_string(),
                    area: "Ingress / Exposure".to_string(),
                    criterion: "TLS-Absicherung für externe HTTP-Endpunkte".to_string(),
                    description: "Ingress-Regel enthält keine TLS-Konfiguration.".to_string(),
                    resource: Some(ResourceReference {
                        kind: "Ingress".to_string(),
                        namespace: ing.metadata.namespace.clone(),
                        name,
                    }),
                    evidence: Evidence {
                        summary: "spec.tls fehlt".to_string(),
                        details: vec![],
                    },
                    risk: "Unverschlüsselte Übertragung oder Fehlkonfiguration möglich".to_string(),
                    recommendation: "TLS-Secret setzen und Redirect auf HTTPS erzwingen."
                        .to_string(),
                    severity: Severity::Medium,
                    heuristic: false,
                });
            }
        }

        Ok(CheckResult {
            check_name: self.name().into(),
            findings,
        })
    }
}
