use super::{human_report, sarif_notification, sarif_report, sarif_rule_id, sarif_uri};
use chainsec::model::{
    CapabilityEvidence, CapabilityReport, Confidence, EngineLimits, FindingType, Location,
    OperationalIssue, PolicySummary, Report, Risk,
};
use std::path::{Path, PathBuf};

fn report_with_capabilities(capabilities: Vec<CapabilityReport>) -> Report {
    let policy = PolicySummary {
        require_lockfile: true,
        offline: false,
        trust_local_input: false,
        allow_insecure_http: false,
        allowed_hosts: Vec::new(),
        limits: (&EngineLimits::default()).into(),
    };
    let mut report = Report::new(PathBuf::from("."), policy);
    report.capabilities = capabilities;
    report
}

fn capability_evidence(suppressed: bool) -> CapabilityEvidence {
    CapabilityEvidence {
        id: "id".to_owned(),
        rule_id: "rule".to_owned(),
        rule_version: 1,
        finding_type: FindingType::NetworkAccess,
        risk: Risk::Low,
        confidence: Confidence::High,
        package: "npm:example".to_owned(),
        file: PathBuf::from("index.js"),
        location: Location {
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: 1,
        },
        matched_code: String::new(),
        suppressed,
        suppression: None,
    }
}

#[test]
fn human_report_excludes_capabilities_with_only_suppressed_evidence() {
    let report = report_with_capabilities(vec![
        CapabilityReport {
            name: "filesystem:read".to_owned(),
            evidence: vec![capability_evidence(true)],
        },
        CapabilityReport {
            name: "network:connect".to_owned(),
            evidence: vec![capability_evidence(false)],
        },
    ]);

    let output = human_report(&report, Risk::Low, false, false);

    assert!(output.contains("1 capability type(s)"));
    assert!(output.contains("Capabilities (1)\n  network:connect"));
    assert!(!output.contains("filesystem:read"));
}

#[test]
fn sarif_includes_unsuppressed_capability_evidence_as_results() {
    let report = report_with_capabilities(vec![CapabilityReport {
        name: "network:connect".to_owned(),
        evidence: vec![capability_evidence(false), capability_evidence(true)],
    }]);

    let sarif = sarif_report(&report, &[]);
    let results = sarif["runs"][0]["results"].as_array().unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["ruleId"], "network:rule");
    assert_eq!(
        results[0]["message"]["text"],
        "Detected network:connect capability evidence"
    );
    assert_eq!(
        results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "index.js"
    );
    assert_eq!(results[0]["partialFingerprints"]["chainsecFindingId"], "id");
}

#[test]
fn sarif_uri_encodes_path_delimiters_and_unicode() {
    assert_eq!(
        sarif_uri(Path::new("src/a file#?.rs")),
        "src/a%20file%23%3F.rs"
    );
    assert_eq!(sarif_uri(Path::new("café.rs")), "caf%C3%A9.rs");
}

#[test]
fn sarif_rule_ids_include_the_rule_group() {
    assert_eq!(
        sarif_rule_id(FindingType::NetworkAccess, "download-code"),
        "network:download-code"
    );
}

#[test]
fn sarif_notifications_include_operational_issue_details() {
    let notification = sarif_notification(&OperationalIssue {
        code: "limit_exceeded".to_owned(),
        message: "scan limit reached".to_owned(),
        package: Some("npm:example".to_owned()),
        operation: "analyze".to_owned(),
        fatal: true,
    });

    assert_eq!(notification["level"], "error");
    assert_eq!(
        notification["message"]["text"],
        "[limit_exceeded] analyze: scan limit reached"
    );
    assert_eq!(notification["properties"]["package"], "npm:example");
    assert_eq!(notification["properties"]["fatal"], true);
}
