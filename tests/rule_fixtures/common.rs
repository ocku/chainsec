use std::fs;

use chainsec::{
    model::{EngineLimits, Language, Rule},
    rules, scanner,
};

pub(crate) struct Case {
    pub(crate) rule_id: &'static str,
    pub(crate) file: &'static str,
    pub(crate) source: &'static str,
}

pub(crate) fn assert_language_extension(rule: &Rule, case: &Case) {
    let expected = match rule.language {
        Language::Python => "case.py",
        Language::JavaScript => "case.js",
        Language::TypeScript => "case.ts",
    };
    assert_eq!(
        case.file, expected,
        "rule {} fixture {} does not match its language {:?}",
        rule.id, case.file, rule.language
    );
}

pub(crate) fn assert_no_match(rule_id: &str, file_name: &str, source: &str) {
    let rules = rules::default_rules();
    let rule = rules
        .iter()
        .find(|rule| rule.id == rule_id)
        .unwrap_or_else(|| panic!("unknown rule {rule_id}"));
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join(file_name), source).unwrap();

    let outcome = scanner::scan(
        directory.path(),
        "fixture",
        std::slice::from_ref(rule),
        &EngineLimits::default(),
    )
    .unwrap_or_else(|error| panic!("scan failed for {rule_id}: {error}"));

    assert!(
        outcome.findings.is_empty(),
        "rule {rule_id} unexpectedly matched:\n{source}"
    );
}
