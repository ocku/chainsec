use chainsec::model::{AnalysisPoint, Report, Risk};
use serde_json::json;

pub(super) fn human_report(report: &Report, color: bool) -> String {
    let mut output = human_report_header(report, color);

    for finding in &report.findings {
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

    output
}

fn human_report_header(report: &Report, color: bool) -> String {
    format!(
        "{} {} — {} package(s), {} finding(s), {} issue(s)\n",
        paint("chainsec", "1;36", color),
        report.tool_version,
        report.statistics.packages,
        report.statistics.findings,
        report.issues.len()
    )
}

fn human_finding(finding: &chainsec::model::AnalysisPoint, color: bool) -> String {
    format!(
        "{} {} {}:{}:{} — {}\n",
        paint(
            &format!("{:?}", finding.risk),
            risk_color(finding.risk),
            color
        ),
        display_rule_id(finding),
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

fn risk_color(risk: Risk) -> &'static str {
    match risk {
        Risk::Low => "34",
        Risk::Medium => "33",
        Risk::High => "31",
        Risk::Critical => "1;31",
    }
}

fn paint(value: &str, color_code: &str, enabled: bool) -> String {
    if enabled {
        format!("\x1b[{color_code}m{value}\x1b[0m")
    } else {
        value.to_owned()
    }
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
        .collect::<Vec<_>>();

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{ "tool": { "driver": { "name": "chainsec", "version": report.tool_version, "rules": rules } }, "results": results }]
    })
}

fn sarif_rule(rule: &chainsec::model::Rule) -> serde_json::Value {
    json!({
        "id": rule.id,
        "name": rule.id,
        "shortDescription": { "text": rule.rationale },
        "help": { "text": rule.remediation },
        "properties": { "version": rule.version, "confidence": format!("{:?}", rule.confidence).to_lowercase() }
    })
}

fn sarif_result(finding: &chainsec::model::AnalysisPoint) -> serde_json::Value {
    json!({
        "ruleId": finding.rule_id,
        "level": sarif_level(finding.risk),
        "message": { "text": finding.rationale },
        "locations": [{ "physicalLocation": {
            "artifactLocation": { "uri": sarif_uri(&finding.file) },
            "region": { "startLine": finding.location.start_line, "startColumn": finding.location.start_column, "endLine": finding.location.end_line, "endColumn": finding.location.end_column }
        }}],
        "partialFingerprints": { "chainsecFindingId": finding.id }
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

pub(super) fn exit_status(report: &Report, threshold: Risk) -> u8 {
    if report
        .issues
        .iter()
        .any(|issue| issue.code == "policy_error" || issue.code == "limit_exceeded")
    {
        return 4;
    }
    if !report.issues.is_empty() {
        return 3;
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
mod tests {
    use super::sarif_uri;
    use std::path::Path;

    #[test]
    fn sarif_uri_encodes_path_delimiters_and_unicode() {
        assert_eq!(
            sarif_uri(Path::new("src/a file#?.rs")),
            "src/a%20file%23%3F.rs"
        );
        assert_eq!(sarif_uri(Path::new("café.rs")), "caf%C3%A9.rs");
    }
}
