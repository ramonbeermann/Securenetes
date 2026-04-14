use std::{fs, net::SocketAddr, path::PathBuf};

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use securenetes::{
    config::AuditConfig, models::AuditReport, reporting, services::audit_runner::run_audit, web,
};

#[derive(Parser, Debug)]
#[command(
    name = "securenetes",
    about = "Kubernetes Security- und C5-orientiertes Audit-Tool"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Audit {
        #[arg(short, long, default_value = "examples/config.yaml")]
        config: PathBuf,
        #[arg(short, long, default_value = "reports")]
        output_dir: PathBuf,
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    Serve {
        #[arg(short, long, default_value = "examples/config.yaml")]
        config: PathBuf,
        #[arg(long, default_value = "127.0.0.1:3000")]
        bind: SocketAddr,
    },
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

    match cli.command {
        Some(Commands::Serve { config, bind }) => {
            let config = load_config(&config)?;
            web::start_server(bind, config).await?;
        }
        Some(Commands::Audit {
            config,
            output_dir,
            format,
        }) => {
            let config = load_config(&config)?;
            run_audit_cli(config, output_dir, format).await?;
        }
        None => {
            let config = load_config(PathBuf::from("examples/config.yaml").as_path())?;
            run_audit_cli(config, PathBuf::from("reports"), OutputFormat::Markdown).await?;
        }
    }

    Ok(())
}

fn load_config(path: &std::path::Path) -> anyhow::Result<AuditConfig> {
    let config_raw = fs::read_to_string(path)
        .with_context(|| format!("Config konnte nicht gelesen werden: {}", path.display()))?;
    let config: AuditConfig = serde_yaml::from_str(&config_raw)?;
    Ok(config)
}

async fn run_audit_cli(
    config: AuditConfig,
    output_dir: PathBuf,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let report: AuditReport = run_audit(config).await?;

    fs::create_dir_all(&output_dir)?;
    let (filename, content) = match format {
        OutputFormat::Markdown => ("report.md", reporting::markdown::render(&report)),
        OutputFormat::Json => ("report.json", reporting::json::render(&report)?),
        OutputFormat::Html => ("report.html", reporting::html::render(&report)),
    };

    let output_path = output_dir.join(filename);
    fs::write(&output_path, content)?;
    println!("Report geschrieben: {}", output_path.display());

    Ok(())
}
