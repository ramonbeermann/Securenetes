pub mod checks;
pub mod config;
pub mod handlers;
pub mod models;
pub mod reporting;
pub mod routes;
pub mod services;
pub mod templates;
pub mod web;

use checks::{
    api_config::ApiServerConfigCheck, etcd::EtcdCheck, images::ImagesCheck,
    ingress::IngressExposureCheck, logging_monitoring::LoggingMonitoringCheck,
    network::NetworkCheck, pod_security::PodSecurityCheck, rbac::RbacCheck, secrets::SecretsCheck,
    tls::TlsWebCheck, Check,
};
use config::AuditConfig;

pub fn build_checks(config: &AuditConfig) -> Vec<Box<dyn Check>> {
    let mut checks: Vec<Box<dyn Check>> = Vec::new();

    if config.checks.rbac {
        checks.push(Box::new(RbacCheck));
    }
    if config.checks.secrets {
        checks.push(Box::new(SecretsCheck));
    }
    if config.checks.pod_security {
        checks.push(Box::new(PodSecurityCheck));
    }
    if config.checks.network {
        checks.push(Box::new(NetworkCheck));
    }
    if config.checks.ingress {
        checks.push(Box::new(IngressExposureCheck));
    }
    if config.checks.images {
        checks.push(Box::new(ImagesCheck));
    }
    if config.checks.logging_monitoring {
        checks.push(Box::new(LoggingMonitoringCheck));
    }
    if config.checks.api_server_config {
        checks.push(Box::new(ApiServerConfigCheck));
    }
    if config.checks.etcd {
        checks.push(Box::new(EtcdCheck));
    }
    if config.checks.tls {
        checks.push(Box::new(TlsWebCheck));
    }

    checks
}
