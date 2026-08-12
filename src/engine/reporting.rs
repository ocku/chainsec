use std::collections::BTreeMap;

use crate::{
    error::Error,
    manifests,
    model::{
        AnalysisPoint, CapabilityEvidence, CapabilityReport, Confidence, FindingType, Language,
        Location, OperationalIssue, PackageReport, Report, Risk,
    },
    scanner,
};

use super::traversal::PendingPackage;

pub(super) fn record_scan(report: &mut Report, scan: scanner::ScanOutcome) -> (u64, u64) {
    let counts = (scan.scanned_files, scan.scanned_bytes);
    report.statistics.source_files += scan.scanned_files;
    report.statistics.source_bytes += scan.scanned_bytes;
    report.issues.extend(scan.issues);
    for finding in scan.findings {
        push_finding(report, finding);
    }
    counts
}

pub(super) fn record_shared_scan(report: &mut Report, scan: &scanner::ScanOutcome) -> (u64, u64) {
    report.statistics.source_files += scan.scanned_files;
    report.statistics.source_bytes += scan.scanned_bytes;
    report.issues.extend(scan.issues.iter().cloned());
    for finding in &scan.findings {
        push_finding(report, finding.clone());
    }

    (scan.scanned_files, scan.scanned_bytes)
}

pub(super) fn record_capabilities(report: &mut Report) {
    let mut capability_evidence = BTreeMap::<String, Vec<CapabilityEvidence>>::new();

    report.findings.retain(|finding| {
        let Some(capability) = finding.capability else {
            return true;
        };
        capability_evidence
            .entry(capability.name().to_owned())
            .or_default()
            .push(CapabilityEvidence {
                id: finding.id.clone(),
                rule_id: finding.rule_id.clone(),
                rule_version: finding.rule_version,
                finding_type: finding.finding_type,
                risk: finding.risk,
                confidence: finding.confidence,
                package: finding.package.clone(),
                file: finding.file.clone(),
                location: finding.location.clone(),
                matched_code: finding.matched_code.clone(),
                suppressed: finding.suppressed,
                suppression: finding.suppression.clone(),
            });
        false
    });

    report.capabilities = capability_evidence
        .into_iter()
        .map(|(name, mut evidence)| {
            evidence.sort_by(|a, b| {
                (&a.package, &a.file, &a.location.start_line, &a.rule_id).cmp(&(
                    &b.package,
                    &b.file,
                    &b.location.start_line,
                    &b.rule_id,
                ))
            });
            CapabilityReport { name, evidence }
        })
        .collect();
}

pub(super) fn record_install_scripts(
    report: &mut Report,
    pending: &PendingPackage,
    warnings: &[manifests::InstallScriptWarning],
) {
    for warning in warnings {
        let relative_manifest = warning
            .manifest
            .strip_prefix(&pending.source)
            .unwrap_or(&warning.manifest);
        let file = relative_manifest.to_string_lossy();
        let matched_code = warning.scripts.join(", ");
        let location = first_line_location();
        let (rule_id, risk, rationale, remediation) = install_script_details(warning.language);

        push_finding(
            report,
            AnalysisPoint {
                id: AnalysisPoint::stable_id(
                    rule_id,
                    1,
                    &pending.package_id,
                    &file,
                    &location,
                    &matched_code,
                ),
                rule_id: rule_id.to_owned(),
                rule_version: 1,
                finding_type: FindingType::InstallScript,
                risk,
                confidence: Confidence::High,
                rationale: rationale.to_owned(),
                remediation: remediation.to_owned(),
                capability: None,
                package: pending.package_id.clone(),
                file: relative_manifest.to_owned(),
                location,
                matched_code,
                suppressed: false,
                suppression: None,
            },
        );
    }
}

fn push_finding(report: &mut Report, finding: AnalysisPoint) {
    let package_findings = report
        .findings
        .iter()
        .filter(|existing| existing.package == finding.package)
        .count() as u64;
    if package_findings >= report.policy.limits.max_findings
        || report
            .findings
            .iter()
            .any(|existing| existing.id == finding.id)
    {
        return;
    }
    report.findings.push(finding);
}

fn first_line_location() -> Location {
    Location {
        start_line: 1,
        start_column: 1,
        end_line: 1,
        end_column: 1,
    }
}

fn install_script_details(language: Language) -> (&'static str, Risk, &'static str, &'static str) {
    match language {
        Language::Python => (
            "chainsec.py.detection.manifest.install-hook",
            Risk::Medium,
            "A Python setup script runs during package installation and can execute arbitrary build-time code.",
            "Review setup.py before installation and prefer declarative packaging configuration.",
        ),
        Language::JavaScript | Language::TypeScript => (
            "chainsec.js.detection.manifest.install-hook",
            Risk::High,
            "An npm lifecycle script runs during package installation and can execute arbitrary commands.",
            "Remove unnecessary lifecycle scripts and review any remaining commands before installation.",
        ),
    }
}

pub(super) fn record_package(
    report: &mut Report,
    pending: &PendingPackage,
    discovery: &manifests::Discovery,
    (scanned_files, scanned_bytes): (u64, u64),
) {
    let dependencies = discovery
        .dependencies
        .iter()
        .map(|dependency| dependency.id())
        .collect();
    let (source_url, resolved_version, digest, cache_hit) =
        pending
            .fetched
            .as_ref()
            .map_or((None, None, None, false), |metadata| {
                (
                    Some(metadata.source_url.clone()),
                    Some(metadata.resolved_version.clone()),
                    Some(metadata.digest.clone()),
                    metadata.cache_hit,
                )
            });

    if cache_hit {
        report.statistics.cache_hits += 1;
    }

    report.packages.push(PackageReport {
        package_id: pending.package_id.clone(),
        source: pending.source.clone(),
        source_url,
        resolved_version,
        digest,
        depth: pending.depth,
        dependencies,
        scanned_files,
        scanned_bytes,
    });
}

pub(super) fn finalize_report(report: &mut Report) {
    report
        .packages
        .sort_by(|a, b| a.package_id.cmp(&b.package_id));
    report.findings.sort_by(|a, b| a.id.cmp(&b.id));
    report.capabilities.sort_by(|a, b| a.name.cmp(&b.name));
    report
        .issues
        .sort_by(|a, b| (&a.code, &a.package, &a.message).cmp(&(&b.code, &b.package, &b.message)));
    report.statistics.packages = report.packages.len() as u64;
    report.statistics.findings = report.findings.len() as u64;
}

pub(super) fn push_issue(
    report: &mut Report,
    error: Error,
    package: Option<String>,
    operation: &str,
    fatal: bool,
) {
    report
        .issues
        .push(operational_issue(error, package, operation, fatal));
}

pub(super) fn operational_issue(
    error: Error,
    package: Option<String>,
    operation: &str,
    fatal: bool,
) -> OperationalIssue {
    OperationalIssue {
        code: error.code().to_owned(),
        message: error.to_string(),
        package,
        operation: operation.to_owned(),
        fatal,
    }
}
