use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    pub profile_name: String,
    pub cluster_name: String,
    pub checks: CheckSelection,
    pub tls_targets: Vec<String>,
    pub email_contacts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckSelection {
    pub rbac: bool,
    pub secrets: bool,
    pub pod_security: bool,
    pub network: bool,
    pub ingress: bool,
    pub images: bool,
    pub logging_monitoring: bool,
    pub api_server_config: bool,
    pub etcd: bool,
    pub tls: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            profile_name: "c5-baseline".to_string(),
            cluster_name: "default-cluster".to_string(),
            checks: CheckSelection {
                rbac: true,
                secrets: true,
                pod_security: true,
                network: true,
                ingress: true,
                images: true,
                logging_monitoring: true,
                api_server_config: true,
                etcd: true,
                tls: true,
            },
            tls_targets: vec![],
            email_contacts: vec![],
        }
    }
}
