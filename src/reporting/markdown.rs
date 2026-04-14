use crate::models::AuditReport;

pub fn render(report: &AuditReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# Securenetes Audit Report ({})\n\n",
        report.profile
    ));
    out.push_str(&format!("- Report-ID: `{}`\n", report.report_id));
    out.push_str(&format!("- Zielcluster: `{}`\n", report.target));
    out.push_str(&format!("- Zeitpunkt: `{}`\n\n", report.generated_at));

    for result in &report.results {
        out.push_str(&format!("## Prüfbereich: {}\n\n", result.check_name));
        if result.findings.is_empty() {
            out.push_str("Keine Feststellungen.\n\n");
            continue;
        }

        for f in &result.findings {
            out.push_str(&format!("### {} - {}\n", f.id, f.title));
            out.push_str(&format!("- **Schweregrad:** {:?}\n", f.severity));
            out.push_str(&format!("- **Prüfkriterium:** {}\n", f.criterion));
            out.push_str(&format!("- **Feststellung:** {}\n", f.description));
            out.push_str(&format!("- **Risiko:** {}\n", f.risk));
            out.push_str(&format!(
                "- **Handlungsempfehlung:** {}\n",
                f.recommendation
            ));
            out.push_str(&format!("- **Evidenz:** {}\n", f.evidence.summary));
            if let Some(r) = &f.resource {
                out.push_str(&format!(
                    "- **Betroffene Ressource:** {}/{} ({})\n",
                    r.namespace.as_deref().unwrap_or("cluster"),
                    r.name,
                    r.kind
                ));
            }
            out.push('\n');
        }
    }

    out
}
