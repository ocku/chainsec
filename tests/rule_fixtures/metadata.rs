use std::{collections::HashSet, fs};

use chainsec::{
    model::{EngineLimits, Language, Risk, Rule},
    rules, scanner,
};

use crate::{common::assert_language_extension, positive};

#[test]
fn every_built_in_rule_has_a_test_case() {
    let all_rules = rules::default_rules();
    let rule_ids: HashSet<&str> = all_rules.iter().map(|rule| rule.id.as_str()).collect();
    let case_ids: HashSet<&str> = positive::cases().map(|case| case.rule_id).collect();

    let missing: Vec<&&str> = rule_ids.difference(&case_ids).collect();
    assert!(missing.is_empty(), "rules without test cases: {missing:?}");
    let unknown: Vec<&&str> = case_ids.difference(&rule_ids).collect();
    assert!(
        unknown.is_empty(),
        "test cases for unknown rules: {unknown:?}"
    );
}

#[test]
fn unverifiable_dynamic_imports_are_medium_risk() {
    let all_rules = rules::default_rules();
    for rule_id in [
        "chainsec.py.detection.dynamic-import",
        "chainsec.js.detection.dynamic-require",
        "chainsec.js.detection.dynamic-import",
        "chainsec.ts.detection.dynamic-require",
        "chainsec.ts.detection.dynamic-import",
    ] {
        let rule = all_rules
            .iter()
            .find(|rule| rule.id == rule_id)
            .unwrap_or_else(|| panic!("unknown rule {rule_id}"));
        assert_eq!(rule.risk, Risk::Medium, "{rule_id} must be medium risk");
    }
}

#[test]
fn every_language_rule_id_starts_with_its_language() {
    for rule in rules::default_rules() {
        let prefix = match rule.language {
            Language::Python => "chainsec.py.",
            Language::JavaScript => "chainsec.js.",
            Language::TypeScript => "chainsec.ts.",
        };
        assert!(
            rule.id.starts_with(prefix),
            "rule {} must start with {prefix}",
            rule.id
        );
    }
}

#[test]
fn every_rule_matches_its_fixture() {
    let all_rules = rules::default_rules();
    for case in positive::cases() {
        let rule: &Rule = all_rules
            .iter()
            .find(|rule| rule.id == case.rule_id)
            .unwrap_or_else(|| panic!("unknown rule {}", case.rule_id));
        assert_language_extension(rule, case);

        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join(case.file);
        fs::write(&file, case.source).unwrap();

        let outcome = scanner::scan(
            directory.path(),
            "fixture",
            std::slice::from_ref(rule),
            &EngineLimits::default(),
        )
        .unwrap_or_else(|error| panic!("scan failed for {}: {error}", case.rule_id));

        assert!(
            outcome
                .findings
                .iter()
                .any(|finding| finding.rule_id == case.rule_id),
            "rule {} did not match its fixture:\n{}",
            case.rule_id,
            case.source
        );
    }
}

#[test]
fn every_rule_compiles() {
    scanner::validate_rules(&rules::default_rules()).unwrap();
}
