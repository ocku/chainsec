use std::collections::{BTreeMap, BTreeSet};

use chainsec::model::{AnalysisPoint, OperationalIssue, Report, Risk};
use serde::Serialize;

use super::{cli::OutputFormat, output::issue_exit_status};

mod human;

const DIFF_SCHEMA_VERSION: &str = "1.0.0";

pub(super) struct VersionReport {
    pub(super) version: String,
    pub(super) report: Report,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DetectionKey {
    group: String,
    rule_id: String,
    risk: Risk,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FindingIdentity {
    package: String,
    rule_id: String,
    rule_version: u32,
    file: std::path::PathBuf,
    location: (usize, usize, usize, usize),
    matched_code: String,
}

#[derive(Debug, Serialize)]
struct DetectionChange {
    group: String,
    rule_id: String,
    risk: Risk,
    before: usize,
    after: usize,
}

#[derive(Debug, Serialize)]
struct CapabilityChange {
    name: String,
    before: usize,
    after: usize,
}

#[derive(Debug, Serialize)]
struct Changes<T> {
    added: Vec<T>,
    removed: Vec<T>,
}

#[derive(Debug, Serialize)]
struct VersionComparison {
    from_version: String,
    to_version: String,
    from_complete: bool,
    to_complete: bool,
    detections: Changes<DetectionChange>,
    capabilities: Changes<CapabilityChange>,
}

#[derive(Debug, Serialize)]
struct VersionIssues<'a> {
    version: &'a str,
    issues: &'a [OperationalIssue],
}

#[derive(Debug, Serialize)]
struct DiffReport<'a> {
    schema_version: &'static str,
    report_type: &'static str,
    tool_version: &'static str,
    package: &'a str,
    resolved_version: &'a str,
    versions: Vec<&'a str>,
    issues: Vec<VersionIssues<'a>>,
    diffs: Vec<VersionComparison>,
}

#[derive(Clone, Copy)]
pub(super) enum Format {
    Human,
    Json,
}

impl TryFrom<OutputFormat> for Format {
    type Error = chainsec::Error;

    fn try_from(format: OutputFormat) -> Result<Self, Self::Error> {
        match format {
            OutputFormat::Human => Ok(Self::Human),
            OutputFormat::Json => Ok(Self::Json),
            OutputFormat::Sarif => Err(chainsec::Error::InvalidConfiguration {
                message:
                    "remote version diffs support only human and JSON output; SARIF represents a single scan"
                        .to_owned(),
            }),
        }
    }
}

#[derive(Clone, Copy)]
enum DetectionFilter {
    Unsuppressed,
    Human { threshold: Risk, verbose: bool },
}

pub(super) fn exit_status(reports: &[VersionReport], threshold: Risk) -> u8 {
    if let Some(status) = reports
        .iter()
        .filter_map(|version| issue_exit_status(&version.report))
        .max()
    {
        return status;
    }

    let Some(newest) = reports.first() else {
        return 0;
    };
    let oldest = reports
        .last()
        .expect("a non-empty report list has a last report");
    let filter = DetectionFilter::Human {
        threshold,
        verbose: false,
    };
    let (added, _) = count_changes(
        &finding_identity_counts(&oldest.report, filter),
        &finding_identity_counts(&newest.report, filter),
    );
    u8::from(!added.is_empty())
}

pub(super) fn render(
    package: &str,
    reports: &[VersionReport],
    format: Format,
    threshold: Risk,
    verbose: bool,
    color: bool,
) -> chainsec::Result<String> {
    let filter = match format {
        Format::Human => DetectionFilter::Human { threshold, verbose },
        Format::Json => DetectionFilter::Unsuppressed,
    };
    let report = build_diff_report(package, reports, filter)?;
    match format {
        Format::Human => Ok(human::render(&report, color)),
        Format::Json => serde_json::to_string_pretty(&report).map_err(|error| {
            chainsec::Error::InvalidConfiguration {
                message: error.to_string(),
            }
        }),
    }
}

fn build_diff_report<'a>(
    package: &'a str,
    reports: &'a [VersionReport],
    filter: DetectionFilter,
) -> chainsec::Result<DiffReport<'a>> {
    let resolved_version = reports
        .first()
        .map(|report| report.version.as_str())
        .ok_or_else(|| chainsec::Error::Resolution {
            package: package.to_owned(),
            message: "registry returned no pullable versions".to_owned(),
        })?;
    let versions = reports
        .iter()
        .map(|report| report.version.as_str())
        .collect();
    let issues = reports
        .iter()
        .filter(|report| !report.report.issues.is_empty())
        .map(|report| VersionIssues {
            version: &report.version,
            issues: &report.report.issues,
        })
        .collect();
    let diffs = reports
        .windows(2)
        .map(|pair| compare_versions(&pair[1], &pair[0], filter))
        .collect();

    Ok(DiffReport {
        schema_version: DIFF_SCHEMA_VERSION,
        report_type: "version_diff",
        tool_version: env!("CARGO_PKG_VERSION"),
        package,
        resolved_version,
        versions,
        issues,
        diffs,
    })
}

fn compare_versions(
    older: &VersionReport,
    newer: &VersionReport,
    filter: DetectionFilter,
) -> VersionComparison {
    let (added_detections, removed_detections) = count_changes(
        &detection_counts(&older.report, filter),
        &detection_counts(&newer.report, filter),
    );
    let (added_capabilities, removed_capabilities) = count_changes(
        &capability_counts(&older.report),
        &capability_counts(&newer.report),
    );

    VersionComparison {
        from_version: older.version.clone(),
        to_version: newer.version.clone(),
        from_complete: older.report.issues.is_empty(),
        to_complete: newer.report.issues.is_empty(),
        detections: Changes {
            added: added_detections
                .into_iter()
                .map(|(key, before, after)| DetectionChange {
                    group: key.group,
                    rule_id: key.rule_id,
                    risk: key.risk,
                    before,
                    after,
                })
                .collect(),
            removed: removed_detections
                .into_iter()
                .map(|(key, before, after)| DetectionChange {
                    group: key.group,
                    rule_id: key.rule_id,
                    risk: key.risk,
                    before,
                    after,
                })
                .collect(),
        },
        capabilities: Changes {
            added: added_capabilities
                .into_iter()
                .map(|(name, before, after)| CapabilityChange {
                    name,
                    before,
                    after,
                })
                .collect(),
            removed: removed_capabilities
                .into_iter()
                .map(|(name, before, after)| CapabilityChange {
                    name,
                    before,
                    after,
                })
                .collect(),
        },
    }
}

fn detection_counts(report: &Report, filter: DetectionFilter) -> BTreeMap<DetectionKey, usize> {
    let mut counts = BTreeMap::new();
    for finding in &report.findings {
        if !include_detection(finding, filter) {
            continue;
        }
        let key = DetectionKey {
            group: finding.finding_type.rule_group().name().to_owned(),
            rule_id: finding.rule_id.clone(),
            risk: finding.risk,
        };
        *counts.entry(key).or_default() += 1;
    }
    counts
}

fn finding_identity_counts(
    report: &Report,
    filter: DetectionFilter,
) -> BTreeMap<FindingIdentity, usize> {
    let mut counts = BTreeMap::new();
    for finding in &report.findings {
        if !include_detection(finding, filter) {
            continue;
        }
        let location = &finding.location;
        let identity = FindingIdentity {
            package: normalized_package_identity(report, &finding.package),
            rule_id: finding.rule_id.clone(),
            rule_version: finding.rule_version,
            file: finding.file.clone(),
            location: (
                location.start_line,
                location.start_column,
                location.end_line,
                location.end_column,
            ),
            matched_code: finding.matched_code.clone(),
        };
        *counts.entry(identity).or_default() += 1;
    }
    counts
}

fn normalized_package_identity(report: &Report, package_id: &str) -> String {
    if package_id == "root" {
        return package_id.to_owned();
    }

    let without_integrity = package_id
        .split_once('#')
        .map_or(package_id, |(identity, _)| identity);
    if let Some(package) = report
        .packages
        .iter()
        .find(|package| package.package_id == package_id)
        && let Some(version) = &package.resolved_version
        && let Some(identity) = without_integrity.strip_suffix(&format!("@{version}"))
    {
        return identity.to_owned();
    }

    without_integrity
        .rsplit_once('@')
        .map_or(without_integrity, |(identity, _)| identity)
        .to_owned()
}

fn include_detection(finding: &AnalysisPoint, filter: DetectionFilter) -> bool {
    match filter {
        DetectionFilter::Unsuppressed => !finding.suppressed,
        DetectionFilter::Human { threshold, verbose } => {
            !finding.suppressed && (verbose || finding.risk >= threshold)
        }
    }
}

fn capability_counts(report: &Report) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for capability in &report.capabilities {
        let count = capability
            .evidence
            .iter()
            .filter(|evidence| !evidence.suppressed)
            .count();
        if count > 0 {
            *counts.entry(capability.name.clone()).or_default() += count;
        }
    }
    counts
}

type CountChange<K> = (K, usize, usize);
type CountChanges<K> = (Vec<CountChange<K>>, Vec<CountChange<K>>);

fn count_changes<K: Ord + Clone>(
    before: &BTreeMap<K, usize>,
    after: &BTreeMap<K, usize>,
) -> CountChanges<K> {
    let keys = before
        .keys()
        .chain(after.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut added = Vec::new();
    let mut removed = Vec::new();

    for key in keys {
        let before_count = before.get(&key).copied().unwrap_or_default();
        let after_count = after.get(&key).copied().unwrap_or_default();
        if after_count > before_count {
            added.push((key, before_count, after_count));
        } else if after_count < before_count {
            removed.push((key, before_count, after_count));
        }
    }
    (added, removed)
}

#[cfg(test)]
mod tests;
