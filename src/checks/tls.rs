use async_trait::async_trait;
use http::header::SERVER;
use kube::Client;
use reqwest::Url;

use crate::{
    checks::Check,
    config::AuditConfig,
    models::{CheckResult, Evidence, Finding, ResourceReference, Severity},
};

pub struct TlsWebCheck;

#[async_trait]
impl Check for TlsWebCheck {
    fn name(&self) -> &'static str {
        "tls"
    }

    async fn run(&self, _client: &Client, config: &AuditConfig) -> anyhow::Result<CheckResult> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()?;

        let mut findings = Vec::new();

        for mail in &config.email_contacts {
            if !is_valid_email(mail) {
                findings.push(Finding {
                    id: format!("TLS-EMAIL-INVALID-{mail}"),
                    title: "Ungültige E-Mail-Adresse in Konfiguration".to_string(),
                    area: "Zusatzprüfungen".to_string(),
                    criterion: "Formale Datenvalidierung".to_string(),
                    description: "E-Mail-Adresse entspricht nicht erwarteten Formatregeln."
                        .to_string(),
                    resource: None,
                    evidence: Evidence {
                        summary: "Regex-basierte E-Mail-Prüfung fehlgeschlagen".to_string(),
                        details: vec![mail.clone()],
                    },
                    risk: "Fehlende Erreichbarkeit von Security-Kontakten".to_string(),
                    recommendation: "Kontaktinformationen korrigieren.".to_string(),
                    severity: Severity::Low,
                    heuristic: false,
                });
            }
        }

        for target in &config.tls_targets {
            let Ok(url) = Url::parse(target) else {
                continue;
            };
            let resp = client.get(url.clone()).send().await;
            match resp {
                Ok(r) => {
                    if url.scheme() != "https" {
                        findings.push(base_web_finding(
                            "TLS-NO-HTTPS",
                            "Endpoint ohne HTTPS",
                            target,
                            "URL verwendet kein HTTPS",
                            Severity::High,
                        ));
                    }

                    let hsts = r.headers().get("strict-transport-security").is_some();
                    if !hsts {
                        findings.push(base_web_finding(
                            "TLS-NO-HSTS",
                            "HSTS Header fehlt",
                            target,
                            "strict-transport-security Header nicht gesetzt",
                            Severity::Medium,
                        ));
                    }

                    if let Some(server) = r.headers().get(SERVER) {
                        findings.push(base_web_finding(
                            "WEB-SERVER-BANNER",
                            "Server-Banner exponiert",
                            target,
                            &format!("server={:?}", server),
                            Severity::Low,
                        ));
                    }
                }
                Err(e) => {
                    findings.push(base_web_finding(
                        "TLS-CONNECT-ERROR",
                        "TLS/Web-Endpoint nicht erreichbar",
                        target,
                        &format!("Fehler beim Verbindungsaufbau: {e}"),
                        Severity::Info,
                    ));
                }
            }
        }

        Ok(CheckResult {
            check_name: self.name().into(),
            findings,
        })
    }
}

fn is_valid_email(value: &str) -> bool {
    let parts: Vec<&str> = value.split('@').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return false;
    }
    parts[1].contains('.') && !parts[1].starts_with('.') && !parts[1].ends_with('.')
}

fn base_web_finding(
    id: &str,
    title: &str,
    endpoint: &str,
    detail: &str,
    severity: Severity,
) -> Finding {
    Finding {
        id: format!("{id}-{endpoint}"),
        title: title.to_string(),
        area: "SSL/TLS & Web Exposure".to_string(),
        criterion: "Transport- und Header-Sicherheit externer Endpunkte".to_string(),
        description: "Exponierter Webdienst zeigt potenzielle Sicherheitslücke.".to_string(),
        resource: Some(ResourceReference {
            kind: "Endpoint".to_string(),
            namespace: None,
            name: endpoint.to_string(),
        }),
        evidence: Evidence {
            summary: detail.to_string(),
            details: vec![detail.to_string()],
        },
        risk: "Erhöhte Angriffsfläche bzw. schwächere Transportabsicherung".to_string(),
        recommendation:
            "TLS-Konfiguration härten, Security Header ergänzen, Exposition reduzieren.".to_string(),
        severity,
        heuristic: false,
    }
}

#[cfg(test)]
mod tests {
    use super::is_valid_email;

    #[test]
    fn validates_email() {
        assert!(is_valid_email("secops@example.org"));
        assert!(!is_valid_email("broken-address"));
    }
}
