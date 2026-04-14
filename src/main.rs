use std::{fs, path::PathBuf};

use anyhow::Context;
use chrono::Utc;
use clap::{Parser, ValueEnum};
use kube::Client;
use securenetes::{
    checks::{
        api_config::ApiServerConfigCheck, etcd::EtcdCheck, images::ImagesCheck,
        ingress::IngressExposureCheck, logging_monitoring::LoggingMonitoringCheck,
        network::NetworkCheck, pod_security::PodSecurityCheck, rbac::RbacCheck,
        secrets::SecretsCheck, tls::TlsWebCheck, Check,
    },
    config::AuditConfig,
    models::AuditReport,
    reporting,
};
use tracing::info;

#[derive(Parser, Debug)]
#[command(
    name = "securenetes",
    about = "Kubernetes Security- und C5-orientiertes Audit-Tool"
)]
struct Cli {
    #[arg(short, long, default_value = "examples/config.yaml")]
    config: PathBuf,
    #[arg(short, long, default_value = "reports")]
    output_dir: PathBuf,
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Markdown)]
    format: OutputFormat,
}

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Markdown,
    Json,
    Html,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let config_raw = fs::read_to_string(&cli.config).with_context(|| {
        format!(
            "Config konnte nicht gelesen werden: {}",
            cli.config.display()
        )
    })?;
    let config: AuditConfig = serde_yaml::from_str(&config_raw)?;

    let client = Client::try_default()
        .await
        .context("Kubernetes Client init fehlgeschlagen")?;
    let checks = build_checks(&config);
    let mut results = Vec::new();

    for check in checks {
        info!("running check: {}", check.name());
        results.push(check.run(&client, &config).await?);
    }

    let report = AuditReport {
        report_id: format!("SNET-{}", Utc::now().format("%Y%m%d%H%M%S")),
        profile: config.profile_name.clone(),
        generated_at: Utc::now(),
        target: config.cluster_name.clone(),
        results,
    };

    fs::create_dir_all(&cli.output_dir)?;
    let (filename, content) = match cli.format {
        OutputFormat::Markdown => ("report.md", reporting::markdown::render(&report)),
        OutputFormat::Json => ("report.json", reporting::json::render(&report)?),
        OutputFormat::Html => ("report.html", reporting::html::render(&report)),
    };

    let output_path = cli.output_dir.join(filename);
    fs::write(&output_path, content)?;
    println!("Report geschrieben: {}", output_path.display());

    Ok(())
}

fn build_checks(config: &AuditConfig) -> Vec<Box<dyn Check>> {
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
