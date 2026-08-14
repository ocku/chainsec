use std::{fs, path::Path};

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
fn javascript_obfuscator_fixtures_are_detected() {
    for fixture in [
        "tests/fixtures/obfuscators/js/javascript-obfuscator-calculator.js",
        "tests/fixtures/obfuscators/js/javascript-obfuscator-compact.js",
        "tests/fixtures/obfuscators/js/javascript-obfuscator-control-flow.js",
        "tests/fixtures/obfuscators/js/javascript-obfuscator-dead-code.js",
        "tests/fixtures/obfuscators/js/javascript-obfuscator-debug-domain.js",
        "tests/fixtures/obfuscators/js/javascript-obfuscator-identifier-dictionary.js",
        "tests/fixtures/obfuscators/js/javascript-obfuscator-identifier-hexadecimal.js",
        "tests/fixtures/obfuscators/js/javascript-obfuscator-identifier-mangled.js",
        "tests/fixtures/obfuscators/js/javascript-obfuscator-identifier-mangled-shuffled.js",
        "tests/fixtures/obfuscators/js/javascript-obfuscator-numbers-to-expressions.js",
        "tests/fixtures/obfuscators/js/javascript-obfuscator-object-keys.js",
        "tests/fixtures/obfuscators/js/javascript-obfuscator-prefix-custom.js",
        "tests/fixtures/obfuscators/js/javascript-obfuscator-preset-high.js",
        "tests/fixtures/obfuscators/js/javascript-obfuscator-properties-unicode.js",
        "tests/fixtures/obfuscators/js/javascript-obfuscator-self-defending.js",
        "tests/fixtures/obfuscators/js/javascript-obfuscator-split-strings.js",
        "tests/fixtures/obfuscators/js/javascript-obfuscator-string-array.js",
        "tests/fixtures/obfuscators/js/javascript-obfuscator-string-array-base64.js",
        "tests/fixtures/obfuscators/js/javascript-obfuscator-string-array-calls.js",
        "tests/fixtures/obfuscators/js/javascript-obfuscator-string-array-rc4.js",
        "tests/fixtures/obfuscators/js/javascript-obfuscator-string-array-rotated.js",
        "tests/fixtures/obfuscators/js/javascript-obfuscator-string-array-wrappers.js",
        "tests/fixtures/obfuscators/js/javascript-obfuscator-target-node.js",
    ] {
        let outcome = scanner::scan(
            Path::new(fixture),
            "fixture",
            &rules::built_in_rules(),
            &EngineLimits::default(),
        )
        .unwrap();

        assert!(
            outcome
                .findings
                .iter()
                .any(|finding| finding.rule_id == "chainsec.js.detection.javascript-obfuscator"),
            "expected javascript-obfuscator detection for {fixture}",
        );
    }
}

#[test]
fn pyarmor_calculator_fixture_is_detected() {
    let fixture = "tests/fixtures/obfuscators/py/pyarmor-calculator.py";
    let outcome = scanner::scan(
        Path::new(fixture),
        "fixture",
        &rules::built_in_rules(),
        &EngineLimits::default(),
    )
    .unwrap();

    for rule_id in [
        "chainsec.py.detection.heuristic.code-protector-marker",
        "chainsec.py.detection.guarddog.pyarmor",
    ] {
        assert!(
            outcome
                .findings
                .iter()
                .any(|finding| finding.rule_id == rule_id),
            "expected {rule_id} detection for {fixture}",
        );
    }
}

#[test]
fn python_source_obfuscator_fixtures_are_detected() {
    for (fixture, rule_id) in [
        (
            "tests/fixtures/obfuscators/py/opy-calculator.py",
            "chainsec.py.detection.dynamic-code-execution",
        ),
        (
            "tests/fixtures/obfuscators/py/pyobfuscate-calculator.py",
            "chainsec.py.detection.ambiguous-identifier",
        ),
    ] {
        let outcome = scanner::scan(
            Path::new(fixture),
            "fixture",
            &rules::built_in_rules(),
            &EngineLimits::default(),
        )
        .unwrap();

        assert!(
            outcome
                .findings
                .iter()
                .any(|finding| finding.rule_id == rule_id),
            "expected {rule_id} detection for {fixture}",
        );
    }
}

#[test]
fn javascript_obfuscator_bootstrap_is_name_independent_and_requires_consistent_identifiers() {
    for (extension, rule_id) in [
        ("js", "chainsec.js.detection.javascript-obfuscator"),
        ("ts", "chainsec.ts.detection.javascript-obfuscator"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let matching_path = directory.path().join(format!("custom-prefix.{extension}"));
        fs::write(
            &matching_path,
            "function chainsecCustomPrefixStrings(){var arbitraryTable=['a','b','c','d'];chainsecCustomPrefixStrings=function(){return arbitraryTable;};return chainsecCustomPrefixStrings();}\n",
        )
        .unwrap();
        let near_miss_path = directory.path().join(format!("near-miss.{extension}"));
        fs::write(
            &near_miss_path,
            "function strings(){var table=['a','b','c','d'];strings=function(){return otherTable;};return strings();}\n",
        )
        .unwrap();
        let rule = rules::built_in_rules()
            .into_iter()
            .find(|rule| rule.id == rule_id)
            .unwrap();

        let matching = scanner::scan(
            &matching_path,
            "fixture",
            std::slice::from_ref(&rule),
            &EngineLimits::default(),
        )
        .unwrap();
        assert_eq!(
            matching.findings.len(),
            1,
            "expected {rule_id} to ignore identifier names"
        );

        let near_miss = scanner::scan(
            &near_miss_path,
            "fixture",
            &[rule],
            &EngineLimits::default(),
        )
        .unwrap();
        assert!(near_miss.findings.is_empty());
    }
}

#[test]
fn lzma_fixture_is_not_detected_as_javascript_obfuscator() {
    let rule = rules::built_in_rules()
        .into_iter()
        .find(|rule| rule.id == "chainsec.js.detection.javascript-obfuscator")
        .unwrap();
    let outcome = scanner::scan(
        Path::new("tests/fixtures/obfuscators/js/lzma.js"),
        "fixture",
        &[rule],
        &EngineLimits::default(),
    )
    .unwrap();

    assert!(outcome.findings.is_empty());
}

#[test]
fn source_size_limit_is_enforced_before_reading() {
    let limits = EngineLimits {
        max_source_file_size: 1,
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
