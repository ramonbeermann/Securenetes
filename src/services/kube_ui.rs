use std::{fs, path::Path};

use anyhow::Context;
use k8s_openapi::api::core::v1::Pod;
use kube::{api::ListParams, Api, Client, Config};
use serde::{Deserialize, Serialize};

const KUBE_UI_CONFIG_PATH: &str = "/data/kube_config.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubeUiConfig {
    pub cluster_url: String,
    pub token: String,
    pub ca_cert: Option<String>,
    pub namespace: Option<String>,
}

pub fn load_kube_ui_config() -> anyhow::Result<Option<KubeUiConfig>> {
    let path = Path::new(KUBE_UI_CONFIG_PATH);
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(path).with_context(|| {
        format!(
            "Kube UI config konnte nicht gelesen werden: {}",
            path.display()
        )
    })?;
    let parsed = serde_json::from_str(&raw).context("Kube UI config ist ungültiges JSON")?;
    Ok(Some(parsed))
}

pub fn save_kube_ui_config(input: &KubeUiConfig) -> anyhow::Result<()> {
    let path = Path::new(KUBE_UI_CONFIG_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "Konfigurationsverzeichnis konnte nicht erstellt werden: {}",
                parent.display()
            )
        })?;
    }

    let payload = serde_json::to_string_pretty(input)?;
    fs::write(path, payload).with_context(|| {
        format!(
            "Kube UI config konnte nicht geschrieben werden: {}",
            path.display()
        )
    })?;

    Ok(())
}

pub async fn build_config_from_ui(input: KubeUiConfig) -> anyhow::Result<Config> {
    let mut config = Config::new(input.cluster_url.parse()?);
    config.auth_info.token = Some(input.token.into());

    if let Some(ca) = input.ca_cert {
        if !ca.trim().is_empty() {
            config.root_cert = Some(vec![ca.into_bytes()]);
        }
    }

    Ok(config)
}

pub async fn test_connection(input: KubeUiConfig) -> anyhow::Result<()> {
    let namespace = input.namespace.clone();
    let config = build_config_from_ui(input).await?;
    let client = Client::try_from(config)?;

    let pods: Api<Pod> = if let Some(ns) = namespace.filter(|ns| !ns.trim().is_empty()) {
        Api::namespaced(client, &ns)
    } else {
        Api::all(client)
    };

    let _ = pods.list(&ListParams::default().limit(1)).await?;
    Ok(())
}
