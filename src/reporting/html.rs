use crate::models::AuditReport;

pub fn render(report: &AuditReport) -> String {
    let mut html = String::from(
        "<html><head><meta charset=\"utf-8\"><title>Securenetes Report</title></head><body>",
    );
    html.push_str(&format!(
        "<h1>Securenetes Audit Report ({})</h1>",
        report.profile
    ));
    html.push_str("<ul>");
    html.push_str(&format!("<li>Report-ID: {}</li>", report.report_id));
    html.push_str(&format!("<li>Zielcluster: {}</li>", report.target));
    html.push_str(&format!("<li>Zeitpunkt: {}</li>", report.generated_at));
    html.push_str("</ul>");
    for result in &report.results {
        html.push_str(&format!("<h2>Prüfbereich: {}</h2>", result.check_name));
        for f in &result.findings {
            html.push_str("<div style='border:1px solid #ccc;padding:10px;margin:8px;'>");
            html.push_str(&format!("<h3>{} - {}</h3>", f.id, f.title));
            html.push_str(&format!("<p><b>Schweregrad:</b> {:?}</p>", f.severity));
            html.push_str(&format!("<p><b>Feststellung:</b> {}</p>", f.description));
            html.push_str(&format!("<p><b>Risiko:</b> {}</p>", f.risk));
            html.push_str(&format!("<p><b>Empfehlung:</b> {}</p>", f.recommendation));
            html.push_str("</div>");
        }
    }
    html.push_str("</body></html>");
    html
}
