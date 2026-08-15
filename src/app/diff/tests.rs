use super::human::{render as human_diff_report, render_total_change};
use super::{
    CapabilityChange, Changes, DetectionChange, DiffReport, Format, VersionComparison,
    VersionReport, count_changes, exit_status, render,
};
use chainsec::model::{
    AnalysisPoint, Confidence, EngineLimits, FindingType, Location, OperationalIssue,
    PolicySummary, Report, Risk,
};
use std::{collections::BTreeMap, path::PathBuf};

fn finding(rule_id: &str, risk: Risk) -> AnalysisPoint {
    AnalysisPoint {
        id: rule_id.to_owned(),
        rule_id: rule_id.to_owned(),
        rule_version: 1,
        finding_type: FindingType::ArbitraryCodeExecution,
        risk,
        confidence: Confidence::High,
        rationale: String::new(),
        remediation: String::new(),
        capability: None,
        package: "npm:example".to_owned(),
        file: PathBuf::from("index.js"),
        location: Location {
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: 1,
        },
        matched_code: String::new(),
        suppressed: false,
        suppression: None,
    }
}

fn version_report(version: &str, findings: Vec<AnalysisPoint>) -> VersionReport {
    let policy = PolicySummary {
        require_lockfile: true,
        offline: false,
        trust_local_input: false,
        allow_insecure_http: false,
        allowed_hosts: Vec::new(),
        limits: (&EngineLimits::default()).into(),
    };
    let mut report = Report::new(PathBuf::from("."), policy);
    report.findings = findings;
    VersionReport {
        version: version.to_owned(),
        report,
    }
}

#[test]
fn diff_exit_status_only_fails_for_threshold_findings_added_between_endpoints() {
    let unchanged = vec![
        version_report("2.0.0", vec![finding("high", Risk::High)]),
        version_report("1.0.0", vec![finding("high", Risk::High)]),
    ];
    assert_eq!(exit_status(&unchanged, Risk::High), 0);

    let added = vec![
        version_report("2.0.0", vec![finding("high", Risk::High)]),
        version_report("1.0.0", Vec::new()),
    ];
    assert_eq!(exit_status(&added, Risk::High), 1);

    let below_threshold = vec![
        version_report("2.0.0", vec![finding("medium", Risk::Medium)]),
        version_report("1.0.0", Vec::new()),
    ];
    assert_eq!(exit_status(&below_threshold, Risk::High), 0);

    let transient = vec![
        version_report("3.0.0", Vec::new()),
        version_report("2.0.0", vec![finding("high", Risk::High)]),
        version_report("1.0.0", Vec::new()),
    ];
    assert_eq!(exit_status(&transient, Risk::High), 0);
}

#[test]
fn diff_exit_status_detects_replaced_occurrences_with_equal_rule_counts() {
    let mut old_occurrence = finding("high", Risk::High);
    old_occurrence.package = "npm:example@1.0.0#sha512-old".to_owned();
    old_occurrence.matched_code = "eval(old_value)".to_owned();
    let mut new_occurrence = finding("high", Risk::High);
    new_occurrence.package = "npm:example@2.0.0#sha512-new".to_owned();
    new_occurrence.location.start_line = 9;
    new_occurrence.location.end_line = 9;
    new_occurrence.matched_code = "eval(new_value)".to_owned();

    assert_eq!(
        exit_status(
            &[
                version_report("2.0.0", vec![new_occurrence]),
                version_report("1.0.0", vec![old_occurrence]),
            ],
            Risk::High,
        ),
        1
    );
}

#[test]
fn diff_exit_status_normalizes_package_versions_for_unchanged_occurrences() {
    let mut old = finding("high", Risk::High);
    old.package = "npm:dependency@1.0.0#sha512-old".to_owned();
    old.matched_code = "eval(value)".to_owned();
    let mut new = old.clone();
    new.package = "npm:dependency@2.0.0#sha512-new".to_owned();

    assert_eq!(
        exit_status(
            &[
                version_report("2.0.0", vec![new]),
                version_report("1.0.0", vec![old]),
            ],
            Risk::High,
        ),
        0
    );
}

#[test]
fn diff_exit_status_ignores_suppressed_new_occurrences() {
    let mut suppressed = finding("high", Risk::High);
    suppressed.suppressed = true;
    assert_eq!(
        exit_status(
            &[
                version_report("2.0.0", vec![suppressed]),
                version_report("1.0.0", Vec::new()),
            ],
            Risk::High,
        ),
        0
    );
}

#[test]
fn json_diff_includes_suppressed_findings_in_detection_counts() {
    let mut suppressed = finding("high", Risk::High);
    suppressed.suppressed = true;
    let reports = [
        version_report("2.0.0", vec![suppressed, finding("high", Risk::High)]),
        version_report("1.0.0", Vec::new()),
    ];

    let output = render(
        "npm:example",
        &reports,
        Format::Json,
        Risk::High,
        false,
        false,
    )
    .expect("JSON diff should render");
    let json: serde_json::Value = serde_json::from_str(&output).expect("valid diff JSON");
    let added = &json["diffs"][0]["detections"]["added"];

    assert_eq!(added.as_array().map(Vec::len), Some(1));
    assert_eq!(added[0]["group"], "execution");
    assert_eq!(added[0]["rule_id"], "high");
    assert_eq!(added[0]["before"], 0);
    assert_eq!(added[0]["after"], 2);
}

#[test]
fn diff_exit_status_preserves_historical_issue_failures() {
    let mut historical = version_report("1.0.0", Vec::new());
    historical.report.issues.push(OperationalIssue {
        code: "analysis_error".to_owned(),
        message: "could not analyze file".to_owned(),
        package: None,
        operation: "analyze".to_owned(),
        fatal: false,
    });
    assert_eq!(
        exit_status(
            &[version_report("2.0.0", Vec::new()), historical],
            Risk::High,
        ),
        3
    );

    let mut policy = version_report("1.0.0", Vec::new());
    policy.report.issues.push(OperationalIssue {
        code: "policy_error".to_owned(),
        message: "lockfile required".to_owned(),
        package: None,
        operation: "resolve".to_owned(),
        fatal: true,
    });
    assert_eq!(
        exit_status(&[version_report("2.0.0", Vec::new()), policy], Risk::High,),
        4
    );
}

#[test]
fn count_changes_classifies_increases_and_decreases() {
    let before = BTreeMap::from([("increased", 1), ("removed", 2), ("unchanged", 3)]);
    let after = BTreeMap::from([("added", 1), ("increased", 4), ("unchanged", 3)]);

    let (added, removed) = count_changes(&before, &after);

    assert_eq!(added, [("added", 0, 1), ("increased", 1, 4)]);
    assert_eq!(removed, [("removed", 2, 0)]);
}

#[test]
fn human_report_shows_total_diffs_and_versions_changed() {
    let detection_added = DetectionChange {
        group: "execution".to_owned(),
        rule_id: "dynamic-code".to_owned(),
        risk: Risk::High,
        before: 0,
        after: 1,
    };
    let detection_removed = DetectionChange {
        group: "execution".to_owned(),
        rule_id: "dynamic-code".to_owned(),
        risk: Risk::High,
        before: 1,
        after: 0,
    };
    let capability_added = CapabilityChange {
        name: "network:connect".to_owned(),
        before: 0,
        after: 3,
    };
    let capability_removed = CapabilityChange {
        name: "network:connect".to_owned(),
        before: 3,
        after: 1,
    };
    let report = DiffReport {
        schema_version: "1.0.0",
        report_type: "version_diff",
        tool_version: "test",
        package: "npm:example",
        resolved_version: "0.1.1",
        versions: vec!["0.1.1", "0.1.0", "0.0.9"],
        issues: Vec::new(),
        diffs: vec![
            VersionComparison {
                from_version: "0.1.0".to_owned(),
                to_version: "0.1.1".to_owned(),
                from_complete: true,
                to_complete: true,
                detections: Changes {
                    added: Vec::new(),
                    removed: vec![detection_removed],
                },
                capabilities: Changes {
                    added: Vec::new(),
                    removed: vec![capability_removed],
                },
                added_findings: Vec::new(),
                removed_findings: Vec::new(),
            },
            VersionComparison {
                from_version: "0.0.9".to_owned(),
                to_version: "0.1.0".to_owned(),
                from_complete: true,
                to_complete: true,
                detections: Changes {
                    added: vec![detection_added],
                    removed: Vec::new(),
                },
                capabilities: Changes {
                    added: vec![capability_added],
                    removed: Vec::new(),
                },
                added_findings: Vec::new(),
                removed_findings: Vec::new(),
            },
        ],
    };

    let plain = human_diff_report(&report, false);
    assert!(plain.starts_with("chainsec diff test — npm:example (3 version(s))\n"));
    assert!(!plain.contains("resolved"));
    assert!(plain.contains("Changes  0.0.9 → 0.1.1"));
    assert!(plain.contains("Detections (1)"));
    assert!(plain.contains("Capabilities (1)"));
    assert!(plain.contains("  +1  network:connect (0 → 1)"));
    assert!(plain.contains("  ±0  High · execution:dynamic-code (0 → 0)"));
    assert_eq!(plain.matches("↳ 0.1.0, 0.1.1").count(), 2);

    let colored = human_diff_report(&report, true);
    assert!(colored.contains("\x1b[1;32m+1\x1b[0m  \x1b[36mnetwork:connect\x1b[0m"));
    assert!(colored.contains("\x1b[2m±0\x1b[0m"));
}

#[test]
fn total_diff_colors_follow_the_net_change() {
    assert_eq!(render_total_change(3, true), "\x1b[1;32m+3\x1b[0m");
    assert_eq!(render_total_change(-2, true), "\x1b[1;31m-2\x1b[0m");
    assert_eq!(render_total_change(0, true), "\x1b[2m±0\x1b[0m");
}
