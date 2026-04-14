use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceReference {
    pub kind: String,
    pub namespace: Option<String>,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub summary: String,
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub area: String,
    pub criterion: String,
    pub description: String,
    pub resource: Option<ResourceReference>,
    pub evidence: Evidence,
    pub risk: String,
    pub recommendation: String,
    pub severity: Severity,
    pub heuristic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CheckResult {
    pub check_name: String,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub report_id: String,
    pub profile: String,
    pub generated_at: DateTime<Utc>,
    pub target: String,
    pub results: Vec<CheckResult>,
}

impl AuditReport {
    pub fn all_findings(&self) -> impl Iterator<Item = &Finding> {
        self.results.iter().flat_map(|r| r.findings.iter())
    }
}
