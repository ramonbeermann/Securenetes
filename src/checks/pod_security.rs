use async_trait::async_trait;
use k8s_openapi::api::core::v1::Pod;
use kube::{api::ListParams, Api, Client};

use crate::{
    checks::Check,
    config::AuditConfig,
    models::{CheckResult, Evidence, Finding, ResourceReference, Severity},
};

pub struct PodSecurityCheck;

#[async_trait]
impl Check for PodSecurityCheck {
    fn name(&self) -> &'static str {
        "pod_security"
    }

    async fn run(&self, client: &Client, _config: &AuditConfig) -> anyhow::Result<CheckResult> {
        let api: Api<Pod> = Api::all(client.clone());
        let mut findings = Vec::new();

        for pod in api.list(&ListParams::default()).await? {
            let pod_name = pod.metadata.name.clone().unwrap_or_default();
            let ns = pod.metadata.namespace.clone();
            if let Some(spec) = pod.spec {
                if spec.host_network.unwrap_or(false)
                    || spec.host_pid.unwrap_or(false)
                    || spec.host_ipc.unwrap_or(false)
                {
                    findings.push(base_finding(
                        "POD-HOST-NS",
                        "Host-Namespace Nutzung erkannt",
                        &pod_name,
                        ns.clone(),
                        "hostNetwork/hostPID/hostIPC aktiviert",
                        Severity::High,
                    ));
                }

                for container in spec.containers {
                    let c_name = container.name;
                    let sc = container.security_context;
                    if sc.as_ref().and_then(|s| s.privileged).unwrap_or(false) {
                        findings.push(base_finding(
                            "POD-PRIV",
                            "Privilegierter Container",
                            &pod_name,
                            ns.clone(),
                            &format!("Container {c_name} privileged=true"),
                            Severity::Critical,
                        ));
                    }

                    if sc
                        .as_ref()
                        .and_then(|s| s.allow_privilege_escalation)
                        .unwrap_or(true)
                    {
                        findings.push(base_finding(
                            "POD-APE",
                            "allowPrivilegeEscalation aktiv/undefiniert",
                            &pod_name,
                            ns.clone(),
                            &format!("Container {c_name} allowPrivilegeEscalation nicht auf false"),
                            Severity::High,
                        ));
                    }

                    if sc.as_ref().and_then(|s| s.read_only_root_filesystem) != Some(true) {
                        findings.push(base_finding(
                            "POD-ROFS",
                            "readOnlyRootFilesystem fehlt",
                            &pod_name,
                            ns.clone(),
                            &format!("Container {c_name} readOnlyRootFilesystem!=true"),
                            Severity::Medium,
                        ));
                    }

                    if container
                        .resources
                        .as_ref()
                        .and_then(|r| r.limits.as_ref())
                        .is_none()
                    {
                        findings.push(base_finding(
                            "POD-LIMITS",
                            "Fehlende Ressourcenlimits",
                            &pod_name,
                            ns.clone(),
                            &format!("Container {c_name} ohne resources.limits"),
                            Severity::Medium,
                        ));
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

fn base_finding(
    id_prefix: &str,
    title: &str,
    pod_name: &str,
    namespace: Option<String>,
    detail: &str,
    severity: Severity,
) -> Finding {
    Finding {
        id: format!("{id_prefix}-{pod_name}"),
        title: title.to_string(),
        area: "Pod Security".to_string(),
        criterion: "Pod Hardening nach Least Privilege".to_string(),
        description: "Sicherheitsrelevante Pod-Konfiguration weicht von Best Practices ab.".to_string(),
        resource: Some(ResourceReference {
            kind: "Pod".to_string(),
            namespace,
            name: pod_name.to_string(),
        }),
        evidence: Evidence {
            summary: detail.to_string(),
            details: vec![detail.to_string()],
        },
        risk: "Erhöhte Privilegien oder schwache Isolation können zur Cluster-Kompromittierung führen."
            .to_string(),
        recommendation:
            "SecurityContext hart setzen (non-root, no privilege escalation, readonly FS, Limits)."
                .to_string(),
        severity,
        heuristic: false,
    }
}
