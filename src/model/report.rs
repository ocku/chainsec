use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::{AnalysisPoint, Location, SerializableLimits};
use crate::model::REPORT_SCHEMA_VERSION;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageReport {
    pub package_id: String,
    pub source: PathBuf,
    pub source_url: Option<String>,
    pub resolved_version: Option<String>,
    pub digest: Option<String>,
    pub depth: usize,
    pub dependencies: Vec<String>,
    pub scanned_files: u64,
    pub scanned_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalIssue {
    pub code: String,
    pub message: String,
    pub package: Option<String>,
    pub operation: String,
    pub fatal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityEvidence {
    pub id: String,
    pub rule_id: String,
    pub rule_version: u32,
    pub finding_type: crate::model::FindingType,
    pub risk: crate::model::Risk,
    pub confidence: crate::model::Confidence,
    pub package: String,
    pub file: PathBuf,
    pub location: Location,
    pub matched_code: String,
    pub suppressed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppression: Option<crate::model::Suppression>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityReport {
    pub name: String,
    pub evidence: Vec<CapabilityEvidence>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanStatistics {
    pub packages: u64,
    pub source_files: u64,
    pub source_bytes: u64,
    pub findings: u64,
    pub cache_hits: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "ReportWire")]
pub struct Report {
    pub schema_version: String,
    pub tool_version: String,
    pub root: PathBuf,
    pub policy: PolicySummary,
    pub packages: Vec<PackageReport>,
    pub findings: Vec<AnalysisPoint>,
    pub capabilities: Vec<CapabilityReport>,
    pub issues: Vec<OperationalIssue>,
    pub statistics: ScanStatistics,
}

impl Report {
    pub fn new(root: PathBuf, policy: PolicySummary) -> Self {
        Self {
            schema_version: REPORT_SCHEMA_VERSION.to_owned(),
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
            root,
            policy,
            packages: Vec::new(),
            findings: Vec::new(),
            capabilities: Vec::new(),
            issues: Vec::new(),
            statistics: ScanStatistics::default(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportWire {
    schema_version: String,
    tool_version: String,
    root: PathBuf,
    policy: PolicySummary,
    packages: Vec<PackageReport>,
    findings: Vec<AnalysisPoint>,
    capabilities: Vec<CapabilityReport>,
    issues: Vec<OperationalIssue>,
    statistics: ScanStatistics,
}

impl TryFrom<ReportWire> for Report {
    type Error = String;

    fn try_from(value: ReportWire) -> Result<Self, Self::Error> {
        const MAX_ITEMS: usize = 1_000_000;
        const MAX_TEXT: usize = 16 * 1024 * 1024;
        if value.schema_version != REPORT_SCHEMA_VERSION {
            return Err(format!(
                "unsupported report schema version: {}",
                value.schema_version
            ));
        }
        if value.packages.len() > MAX_ITEMS
            || value.findings.len() > MAX_ITEMS
            || value.capabilities.len() > MAX_ITEMS
            || value.issues.len() > MAX_ITEMS
        {
            return Err("report contains too many items".to_owned());
        }
        if value.tool_version.len() > MAX_TEXT {
            return Err("report tool_version is too large".to_owned());
        }
        if value.statistics.packages != value.packages.len() as u64
            || value.statistics.findings != value.findings.len() as u64
        {
            return Err("report statistics do not match report contents".to_owned());
        }
        for finding in &value.findings {
            if finding.id.is_empty()
                || finding.rule_id.is_empty()
                || finding.package.is_empty()
                || finding.matched_code.len() > MAX_TEXT
                || !valid_location(&finding.location)
            {
                return Err("invalid finding in report".to_owned());
            }
        }
        for capability in &value.capabilities {
            for evidence in &capability.evidence {
                if !valid_location(&evidence.location) {
                    return Err("invalid capability evidence in report".to_owned());
                }
            }
        }
        Ok(Self {
            schema_version: value.schema_version,
            tool_version: value.tool_version,
            root: value.root,
            policy: value.policy,
            packages: value.packages,
            findings: value.findings,
            capabilities: value.capabilities,
            issues: value.issues,
            statistics: value.statistics,
        })
    }
}

fn valid_location(location: &Location) -> bool {
    location.start_line > 0
        && location.start_column > 0
        && location.end_line > 0
        && location.end_column > 0
        && (location.end_line > location.start_line || location.end_column >= location.start_column)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySummary {
    pub require_lockfile: bool,
    pub offline: bool,
    pub trust_local_input: bool,
    pub allow_insecure_http: bool,
    pub allowed_hosts: Vec<String>,
    pub limits: SerializableLimits,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, EngineLimits, FindingType, Risk};
    use serde_json::Value;

    fn report_json() -> Value {
        let mut report = Report::new(
            PathBuf::from("."),
            PolicySummary {
                require_lockfile: false,
                offline: false,
                trust_local_input: false,
                allow_insecure_http: false,
                allowed_hosts: Vec::new(),
                limits: SerializableLimits::from(&EngineLimits::default()),
            },
        );
        report.findings.push(AnalysisPoint {
            id: "finding-1".to_owned(),
            rule_id: "rule-1".to_owned(),
            rule_version: 1,
            finding_type: FindingType::FileAnalysis,
            risk: Risk::Low,
            confidence: Confidence::High,
            rationale: "rationale".to_owned(),
            remediation: "remediation".to_owned(),
            capability: None,
            package: "package".to_owned(),
            file: PathBuf::from("file.js"),
            location: Location {
                start_line: 2,
                start_column: 3,
                end_line: 2,
                end_column: 4,
            },
            matched_code: "code".to_owned(),
            suppressed: false,
            suppression: None,
        });
        report.statistics.findings = 1;
        serde_json::to_value(report).unwrap()
    }

    #[test]
    fn rejects_invalid_report_coordinates() {
        for (field, value) in [("start_column", 0), ("end_column", 0)] {
            let mut json = report_json();
            json["findings"][0]["location"][field] = value.into();
            assert!(serde_json::from_value::<Report>(json).is_err());
        }

        let mut json = report_json();
        json["findings"][0]["location"]["end_column"] = 2.into();
        assert!(serde_json::from_value::<Report>(json).is_err());
    }

    #[test]
    fn rejects_unknown_report_fields() {
        let mut json = report_json();
        json["unexpected"] = Value::Bool(true);
        assert!(serde_json::from_value::<Report>(json).is_err());
    }
}
