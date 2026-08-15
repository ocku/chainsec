use std::fs;

use super::super::*;
use crate::rules::default_rules as built_in_rules;

#[test]
fn structured_literal_detection_is_composable_and_case_insensitive() {
    let structured = [
        "https://example.com/resource",
        "Fetch from https://example.com/resource with the supplied token",
        "select token from sessions where active = true",
        r"r'^(?:[a-z]+)$'",
        "User {user_id:08x} requested {resource}",
        "This is ordinary documentation.",
    ];
    let opaque = [
        "nQ8zP4vLm7T2rX9aBcDeFgHiJkNoPqRsTuVwY3Z5mK6sA1bC8dE0fG9hI2jL7pR",
        "a string with no structural markers",
    ];

    for value in structured {
        assert!(
            super::super::entropy::is_structured_literal(value),
            "expected structured: {value}"
        );
    }
    for value in opaque {
        assert!(
            !super::super::entropy::is_structured_literal(value),
            "expected opaque: {value}"
        );
    }
}

#[test]
fn scanner_detects_shebang_and_case_insensitive_source_files() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("postinstall"),
        "#!/usr/bin/env python3\neval(payload)\n",
    )
    .unwrap();
    fs::write(directory.path().join("UPPER.PY"), "eval(payload)\n").unwrap();
    fs::write(
        directory.path().join("launcher"),
        "#!/usr/bin/env node\neval(payload)\n",
    )
    .unwrap();
    fs::write(directory.path().join("UPPER.JS"), "eval(payload)\n").unwrap();

    fs::write(directory.path().join("UPPER.TS"), "eval(payload)\n").unwrap();

    let outcome = scan(
        directory.path(),
        "root",
        &built_in_rules(),
        &EngineLimits::default(),
    )
    .unwrap();

    for file in [
        "postinstall",
        "UPPER.PY",
        "launcher",
        "UPPER.JS",
        "UPPER.TS",
    ] {
        assert!(
            outcome
                .findings
                .iter()
                .any(|finding| finding.file == Path::new(file)),
            "expected a syntax finding for {file}"
        );
    }
}

#[test]
fn scanner_detects_javascript_and_typescript_jsx_sources() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("payload.jsx"),
        "const view = <div />;\neval(input);\n",
    )
    .unwrap();
    fs::write(
        directory.path().join("payload.tsx"),
        "const view: JSX.Element = <div />;\neval(input);\n",
    )
    .unwrap();

    let outcome = scan(
        directory.path(),
        "root",
        &built_in_rules(),
        &EngineLimits::default(),
    )
    .unwrap();

    assert!(outcome.findings.iter().any(|finding| {
        finding.file == Path::new("payload.jsx")
            && finding.rule_id == "chainsec.js.detection.dynamic-code-execution"
    }));
    assert!(outcome.findings.iter().any(|finding| {
        finding.file == Path::new("payload.tsx")
            && finding.rule_id == "chainsec.ts.detection.dynamic-code-execution"
    }));
}

#[test]
fn scanner_does_not_report_recovered_parse_errors_by_default_or_skip_analysis() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("malformed.js"), "eval(input); {\n").unwrap();

    let outcome = scan(
        directory.path(),
        "root",
        &built_in_rules(),
        &EngineLimits::default(),
    )
    .unwrap();

    assert!(
        outcome
            .issues
            .iter()
            .all(|issue| issue.code != "parse_error")
    );
    assert!(
        outcome
            .findings
            .iter()
            .any(|finding| finding.rule_id == "chainsec.js.detection.dynamic-code-execution")
    );
}

#[test]
fn scanner_marks_recovered_parse_errors_fatal_without_skipping_analysis() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("malformed.js"), "eval(input); {\n").unwrap();
    let limits = EngineLimits {
        fail_on_parse_error: true,
        ..EngineLimits::default()
    };

    let outcome = scan(directory.path(), "root", &built_in_rules(), &limits).unwrap();

    assert!(
        outcome
            .issues
            .iter()
            .any(|issue| issue.code == "parse_error" && issue.fatal)
    );
    assert!(
        outcome
            .findings
            .iter()
            .any(|finding| finding.rule_id == "chainsec.js.detection.dynamic-code-execution")
    );
}
