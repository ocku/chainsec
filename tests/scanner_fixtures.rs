use std::path::Path;

use chainsec::{model::EngineLimits, rules, scanner};

#[test]
fn positive_and_negative_language_fixtures_are_scanned() {
    let outcome = scanner::scan(
        Path::new("tests/fixtures/scanner"),
        "fixture",
        &rules::built_in_rules(),
        &EngineLimits::default(),
    )
    .unwrap();
    assert!(
        outcome
            .findings
            .iter()
            .any(|finding| finding.file.ends_with("positive.py"))
    );
    assert!(
        outcome
            .findings
            .iter()
            .any(|finding| finding.file.ends_with("positive.js"))
    );
    assert!(
        outcome
            .findings
            .iter()
            .any(|finding| finding.file.ends_with("positive.ts"))
    );
    assert!(
        !outcome
            .findings
            .iter()
            .any(|finding| finding.file.to_string_lossy().contains("negative"))
    );
    assert!(
        outcome
            .findings
            .iter()
            .all(|finding| finding.id.starts_with("sha256:") && finding.rule_version == 1)
    );
}

#[test]
fn source_size_limit_is_enforced_before_reading() {
    let limits = EngineLimits {
        max_source_file_bytes: 1,
        ..EngineLimits::default()
    };
    let error = scanner::scan(
        Path::new("tests/fixtures/scanner"),
        "fixture",
        &rules::built_in_rules(),
        &limits,
    )
    .unwrap_err();
    assert_eq!(error.code(), "limit_exceeded");
}
