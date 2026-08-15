use std::fs;

use super::super::*;
use crate::{
    model::{Confidence, FindingType, Risk},
    rules::default_rules as built_in_rules,
};

#[test]
fn duplicate_source_matches_do_not_consume_the_finding_budget() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("duplicate.js"), "eval(input);\n").unwrap();
    let duplicate_rule = Rule {
        id: "duplicate-eval".to_owned(),
        version: 1,
        language: Language::JavaScript,
        finding_type: FindingType::ArbitraryCodeExecution,
        risk: Risk::High,
        confidence: Confidence::High,
        rationale: "test".to_owned(),
        remediation: "test".to_owned(),
        capability: None,
        query: "(call_expression function: (identifier) @match (#eq? @match \"eval\"))".to_owned(),
        entropy: None,
    };
    let limits = EngineLimits {
        max_findings: 1,
        ..EngineLimits::default()
    };

    let outcome = scan(
        directory.path(),
        "root",
        &[duplicate_rule.clone(), duplicate_rule],
        &limits,
    )
    .unwrap();
    assert_eq!(outcome.findings.len(), 1);
}

#[test]
fn duplicate_finding_ids_keep_the_highest_risk_representative() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("duplicate.js"), "eval(input);\n").unwrap();
    let low_rule = Rule {
        id: "duplicate-eval-risk".to_owned(),
        version: 1,
        language: Language::JavaScript,
        finding_type: FindingType::ArbitraryCodeExecution,
        risk: Risk::Low,
        confidence: Confidence::High,
        rationale: "test".to_owned(),
        remediation: "test".to_owned(),
        capability: None,
        query: "(call_expression function: (identifier) @match (#eq? @match \"eval\"))".to_owned(),
        entropy: None,
    };
    let mut critical_rule = low_rule.clone();
    critical_rule.risk = Risk::Critical;
    let limits = EngineLimits {
        max_findings: 2,
        ..EngineLimits::default()
    };

    let outcome = scan(
        directory.path(),
        "root",
        &[low_rule, critical_rule],
        &limits,
    )
    .unwrap();

    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(outcome.findings[0].risk, Risk::Critical);
}

#[test]
fn scanner_enforces_the_source_file_budget() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("first.js"), "const first = 1;\n").unwrap();
    fs::write(directory.path().join("second.js"), "const second = 2;\n").unwrap();
    let limits = EngineLimits {
        max_source_files: 1,
        ..EngineLimits::default()
    };

    let error = scan(directory.path(), "root", &built_in_rules(), &limits).unwrap_err();

    assert!(matches!(
        error,
        Error::LimitExceeded { ref resource, limit: 1 } if resource == "source files"
    ));
}

#[test]
fn scanner_enforces_the_finding_budget() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("repeated.js"),
        "eval(input);\neval(input);\neval(input);\n",
    )
    .unwrap();
    let limits = EngineLimits {
        max_findings: 2,
        ..EngineLimits::default()
    };

    let outcome = scan(directory.path(), "root", &built_in_rules(), &limits).unwrap();

    assert_eq!(
        outcome
            .findings
            .iter()
            .filter(|finding| finding.capability.is_none())
            .count(),
        2
    );
    assert!(outcome.issues.iter().any(|issue| {
        issue.code == "limit_exceeded"
            && issue.operation == "source scanning"
            && issue.message.contains("findings limit exceeded")
    }));
}
