use async_trait::async_trait;
use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding};
use kube::{api::ListParams, Api, Client};

use crate::{
    checks::Check,
    config::AuditConfig,
    models::{CheckResult, Evidence, Finding, ResourceReference, Severity},
};

pub struct RbacCheck;

#[async_trait]
impl Check for RbacCheck {
    fn name(&self) -> &'static str {
        "rbac"
    }

    async fn run(&self, client: &Client, _config: &AuditConfig) -> anyhow::Result<CheckResult> {
        let cr_api: Api<ClusterRole> = Api::all(client.clone());
        let crb_api: Api<ClusterRoleBinding> = Api::all(client.clone());

        let mut findings = Vec::new();

        for role in cr_api.list(&ListParams::default()).await? {
            if let Some(rules) = role.rules.as_ref() {
                let wildcard = rules.iter().any(|r| {
                    r.verbs.iter().flatten().any(|v| v == "*")
                        || r.resources.iter().flatten().any(|res| res == "*")
                });
                if wildcard {
                    findings.push(Finding {
                        id: format!(
                            "RBAC-WILDCARD-{}",
                            role.metadata.name.clone().unwrap_or_default()
                        ),
                        title: "Wildcard-Berechtigungen erkannt".to_string(),
                        area: "RBAC".to_string(),
                        criterion: "Rollen dürfen nicht unbeschränkt (*) berechtigen".to_string(),
                        description: "ClusterRole enthält Wildcards in verbs/resources."
                            .to_string(),
                        resource: Some(ResourceReference {
                            kind: "ClusterRole".to_string(),
                            namespace: None,
                            name: role.metadata.name.clone().unwrap_or_default(),
                        }),
                        evidence: Evidence {
                            summary: "Wildcard in Rule gefunden".to_string(),
                            details: vec![format!("rules={:?}", rules)],
                        },
                        risk: "Missbrauch mit vollständiger Clusterkontrolle möglich".to_string(),
                        recommendation:
                            "Least-Privilege durch explizite verbs/resources implementieren."
                                .to_string(),
                        severity: Severity::Critical,
                        heuristic: false,
                    });
                }
            }
        }

        for binding in crb_api.list(&ListParams::default()).await? {
            if let Some(role_ref) = binding
                .role_ref
                .api_group
                .as_ref()
                .map(|_| &binding.role_ref.name)
            {
                if role_ref == "cluster-admin" {
                    findings.push(Finding {
                        id: format!(
                            "RBAC-CRB-CLUSTERADMIN-{}",
                            binding.metadata.name.clone().unwrap_or_default()
                        ),
                        title: "ClusterRoleBinding auf cluster-admin".to_string(),
                        area: "RBAC".to_string(),
                        criterion: "Kritische Rollenbindungen sind zu minimieren".to_string(),
                        description: "Binding delegiert cluster-admin-Rechte.".to_string(),
                        resource: Some(ResourceReference {
                            kind: "ClusterRoleBinding".to_string(),
                            namespace: None,
                            name: binding.metadata.name.clone().unwrap_or_default(),
                        }),
                        evidence: Evidence {
                            summary: "roleRef.name=cluster-admin".to_string(),
                            details: vec![format!("subjects={:?}", binding.subjects)],
                        },
                        risk: "Vollständige Rechte für gebundene Subjects".to_string(),
                        recommendation:
                            "Binding entfernen oder auf minimal erforderliche Rolle reduzieren."
                                .to_string(),
                        severity: Severity::High,
                        heuristic: false,
                    });
                }
            }
        }

        Ok(CheckResult {
            check_name: self.name().into(),
            findings,
        })
    }
}
