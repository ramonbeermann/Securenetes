pub mod api_config;
pub mod etcd;
pub mod images;
pub mod ingress;
pub mod logging_monitoring;
pub mod network;
pub mod pod_security;
pub mod rbac;
pub mod secrets;
pub mod tls;

use async_trait::async_trait;
use kube::Client;

use crate::{config::AuditConfig, models::CheckResult};

#[async_trait]
pub trait Check: Send + Sync {
    fn name(&self) -> &'static str;
    async fn run(&self, client: &Client, config: &AuditConfig) -> anyhow::Result<CheckResult>;
}
