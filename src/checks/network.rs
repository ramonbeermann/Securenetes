use std::collections::HashSet;

use async_trait::async_trait;
use k8s_openapi::api::{core::v1::Namespace, networking::v1::NetworkPolicy};
use kube::{api::ListParams, Api, Client, ResourceExt};

use crate::{
    checks::Check,
    config::AuditConfig,
    models::{CheckResult, Evidence, Finding, ResourceReference, Severity},
};

pub struct NetworkCheck;

#[async_trait]
impl Check for NetworkCheck {
    fn name(&self) -> &'static str {
        "network"
    }

    async fn run(&self, client: &Client, _config: &AuditConfig) -> anyhow::Result<CheckResult> {
        let ns_api: Api<Namespace> = Api::all(client.clone());
        let np_api: Api<NetworkPolicy> = Api::all(client.clone());

        let namespaces: Vec<String> = ns_api
            .list(&ListParams::default())
            .await?
            .into_iter()
            .map(|n| n.name_any())
            .collect();

        let policy_namespaces: HashSet<String> = np_api
            .list(&ListParams::default())
            .await?
            .iter()
            .filter_map(|p| p.metadata.namespace.clone())
            .collect();

        let mut findings = Vec::new();
        for ns in namespaces {
            if !policy_namespaces.contains(&ns) {
                findings.push(Finding {
                    id: format!("NET-NOPOLICY-{ns}"),
                    title: "Namespace ohne NetworkPolicy".to_string(),
                    area: "Network Policies".to_string(),
                    criterion: "Segmentierung pro Namespace".to_string(),
                    description: "Für den Namespace wurden keine NetworkPolicies gefunden."
                        .to_string(),
                    resource: Some(ResourceReference {
                        kind: "Namespace".to_string(),
                        namespace: None,
                        name: ns.clone(),
                    }),
                    evidence: Evidence {
                        summary: "Keine Policyobjekte im Namespace".to_string(),
                        details: vec!["Zero-trust Segmentierung nicht nachweisbar".to_string()],
                    },
                    risk: "Unnötig offene Ost-West-Kommunikation möglich".to_string(),
                    recommendation: "Default-Deny + explizite Allow-Policies einführen."
                        .to_string(),
                    severity: Severity::High,
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
