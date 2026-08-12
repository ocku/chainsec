use std::collections::{BTreeMap, BTreeSet};

use chainsec::model::{AnalysisPoint, CapabilityEvidence, Report, Risk};
use serde_json::json;

use super::style::{paint, risk_color};

const HEURISTICS_URL: &str = "github.com/ocku/chainsec/docs/HEURISTICS.md";

pub(super) fn human_report(report: &Report, threshold: Risk, verbose: bool, color: bool) -> String {
    let mut output = human_report_header(report, color);
    let findings = report
        .findings
        .iter()
        .filter(|finding| !finding.suppressed && (verbose || finding.risk >= threshold))
        .collect::<Vec<_>>();

    let has_findings = !findings.is_empty();
    for finding in findings {
        output.push_str(&human_finding(finding, color));
    }

    for issue in &report.issues {
        output.push_str(&format!(
            "{} [{}] {}\n",
            paint("issue", "33", color),
            issue.code,
            issue.message
        ));
    }

    output.push_str(&human_summary(report, threshold, verbose, color));
    if has_findings {
        output.push_str(&format!(
            "\n{}\n",
            paint(
                &format!(
                    "You can check out what each heuristic means at {}",
                    HEURISTICS_URL
                ),
                "2",
                color
            )
        ));
    }
    output
}

fn human_summary(report: &Report, threshold: Risk, verbose: bool, color: bool) -> String {
    let capabilities = report
        .capabilities
        .iter()
        .filter(|capability| {
            capability
                .evidence
                .iter()
                .any(|evidence| !evidence.suppressed)
        })
        .map(|capability| capability.name.as_str())
        .collect::<BTreeSet<_>>();
    let mut alerts = BTreeMap::<Risk, BTreeMap<String, usize>>::new();

    for finding in &report.findings {
        if !finding.suppressed && (verbose || finding.risk >= threshold) {
            *alerts
                .entry(finding.risk)
                .or_default()
                .entry(display_rule_id(finding))
                .or_default() += 1;
        }
    }

    let alert_count = alerts.values().map(BTreeMap::len).sum::<usize>();
    let mut output = format!(
        "\n{}\n{}\n{} ({})\n",
        paint("Summary", "1;36", color),
        paint("───────", "36", color),
        paint("Capabilities", "1", color),
        capabilities.len(),
    );

    if capabilities.is_empty() {
        output.push_str(&format!("  {}\n", paint("none", "2", color)));
    } else {
        for capability in capabilities {
            output.push_str(&format!("  {}\n", paint(capability, "36", color)));
        }
    }

    output.push_str(&format!(
        "{} ({alert_count})\n",
        paint("Alerts", "1", color),
    ));
    if alerts.is_empty() {
        output.push_str(&format!("  {}\n", paint("none", "2", color)));
        return output;
    }

    for risk in [Risk::Critical, Risk::High, Risk::Medium, Risk::Low] {
        let Some(rules) = alerts.get(&risk) else {
            continue;
        };
        for (rule, count) in rules {
            let label = format!("{risk:?}");
            let count = format!("{count:>3}");
            output.push_str(&format!(
                "  {} {}  {}\n",
                paint(&format!("{label:<8}"), risk_color(risk), color),
                paint(&count, "1", color),
                paint(rule, "36", color),
            ));
        }
    }
    output
}

fn human_report_header(report: &Report, color: bool) -> String {
    format!(
        "{} {} — {} package(s), {} source file(s), {} source byte(s), {} finding(s), {} capability type(s), {} issue(s)\n",
        paint("chainsec", "1;36", color),
        report.tool_version,
        report.statistics.packages,
        report.statistics.source_files,
        report.statistics.source_bytes,
        report.statistics.findings,
        report
            .capabilities
            .iter()
            .filter(|capability| capability
                .evidence
                .iter()
                .any(|evidence| !evidence.suppressed))
            .count(),
        report.issues.len()
    )
}

fn human_finding(finding: &AnalysisPoint, color: bool) -> String {
    format!(
        "{} {} [{}] {}:{}:{} — {}\n",
        paint(
            &format!("{:?}", finding.risk),
            risk_color(finding.risk),
            color
        ),
        display_rule_id(finding),
        finding.package,
        finding.file.display(),
        finding.location.start_line,
        finding.location.start_column,
        finding.matched_code.replace('\n', " ")
    )
}

fn display_rule_id(finding: &AnalysisPoint) -> String {
    format!(
        "{}:{}",
        finding.finding_type.rule_group().name(),
        finding.rule_id
    )
}

pub(super) fn sarif_report(
    report: &Report,
    configured_rules: &[chainsec::model::Rule],
) -> serde_json::Value {
    let rules = configured_rules.iter().map(sarif_rule).collect::<Vec<_>>();
    let results = report
        .findings
        .iter()
        .filter(|finding| !finding.suppressed)
        .map(sarif_result)
        .chain(report.capabilities.iter().flat_map(|capability| {
            capability
                .evidence
                .iter()
                .filter(|evidence| !evidence.suppressed)
                .map(|evidence| sarif_capability_result(evidence, &capability.name))
        }))
        .collect::<Vec<_>>();
    let notifications = report
        .issues
        .iter()
        .map(sarif_notification)
        .collect::<Vec<_>>();

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": { "name": "chainsec", "version": report.tool_version, "rules": rules } },
            "invocations": [{
                "executionSuccessful": report.issues.is_empty(),
                "toolExecutionNotifications": notifications
            }],
            "results": results
        }]
    })
}

fn sarif_rule(rule: &chainsec::model::Rule) -> serde_json::Value {
    let id = sarif_rule_id(rule.finding_type, &rule.id);
    json!({
        "id": id,
        "name": id,
        "shortDescription": { "text": rule.rationale },
        "help": { "text": rule.remediation },
        "properties": { "version": rule.version, "confidence": format!("{:?}", rule.confidence).to_lowercase() }
    })
}

fn sarif_rule_id(finding_type: chainsec::model::FindingType, rule_id: &str) -> String {
    format!("{}:{rule_id}", finding_type.rule_group().name())
}

fn sarif_result(finding: &chainsec::model::AnalysisPoint) -> serde_json::Value {
    json!({
        "ruleId": sarif_rule_id(finding.finding_type, &finding.rule_id),
        "level": sarif_level(finding.risk),
        "message": { "text": finding.rationale },
        "locations": [{ "physicalLocation": {
            "artifactLocation": { "uri": sarif_uri(&finding.file) },
            "region": { "startLine": finding.location.start_line, "startColumn": finding.location.start_column, "endLine": finding.location.end_line, "endColumn": finding.location.end_column }
        }}],
        "partialFingerprints": { "chainsecFindingId": finding.id }
    })
}

fn sarif_capability_result(
    evidence: &CapabilityEvidence,
    capability_name: &str,
) -> serde_json::Value {
    json!({
        "ruleId": sarif_rule_id(evidence.finding_type, &evidence.rule_id),
        "level": sarif_level(evidence.risk),
        "message": { "text": format!("Detected {capability_name} capability evidence") },
        "locations": [{ "physicalLocation": {
            "artifactLocation": { "uri": sarif_uri(&evidence.file) },
            "region": { "startLine": evidence.location.start_line, "startColumn": evidence.location.start_column, "endLine": evidence.location.end_line, "endColumn": evidence.location.end_column }
        }}],
        "partialFingerprints": { "chainsecFindingId": evidence.id }
    })
}

fn sarif_notification(issue: &chainsec::model::OperationalIssue) -> serde_json::Value {
    let level = if issue.fatal { "error" } else { "warning" };
    let package = issue.package.as_deref().unwrap_or("");
    json!({
        "level": level,
        "message": { "text": format!("[{}] {}: {}", issue.code, issue.operation, issue.message) },
        "properties": {
            "code": issue.code,
            "operation": issue.operation,
            "package": package,
            "fatal": issue.fatal
        }
    })
}

fn sarif_level(risk: Risk) -> &'static str {
    match risk {
        Risk::Low => "note",
        Risk::Medium => "warning",
        Risk::High | Risk::Critical => "error",
    }
}

fn sarif_uri(path: &std::path::Path) -> String {
    let path = path.to_string_lossy().replace('\\', "/");
    let mut uri = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
            uri.push(byte as char);
        } else {
            uri.push('%');
            uri.push_str(&format!("{byte:02X}"));
        }
    }
    uri
}

pub(super) fn issue_exit_status(report: &Report) -> Option<u8> {
    if report
        .issues
        .iter()
        .any(|issue| issue.code == "policy_error" || issue.code == "limit_exceeded")
    {
        return Some(4);
    }
    (!report.issues.is_empty()).then_some(3)
}

pub(super) fn exit_status(report: &Report, threshold: Risk) -> u8 {
    if let Some(status) = issue_exit_status(report) {
        return status;
    }
    if report
        .findings
        .iter()
        .any(|finding| !finding.suppressed && finding.risk >= threshold)
    {
        return 1;
    }
    0
}

#[cfg(test)]
mod tests;
