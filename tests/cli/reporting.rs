use std::process::Command;

#[test]
fn json_report_has_versioned_contract() {
    let cache = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .args([
            "scan",
            "tests/fixtures/scanner",
            "--format",
            "json",
            "--max-package-depth",
            "0",
            "--cache",
            cache.path().to_str().unwrap(),
            "--fail-on",
            "critical",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], "1.2.0");
    assert_eq!(report["policy"]["allow_insecure_http"], false);
    assert!(report["findings"].as_array().unwrap().len() >= 3);
    let evidence = report["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|capability| capability["evidence"].as_array().unwrap())
        .next()
        .expect("fixture should produce capability evidence");
    for field in [
        "id",
        "rule_id",
        "rule_version",
        "finding_type",
        "risk",
        "confidence",
        "package",
        "file",
        "location",
        "matched_code",
        "suppressed",
    ] {
        assert!(evidence.get(field).is_some(), "missing {field}");
    }
    assert_eq!(report["statistics"]["packages"], 1);
}

#[test]
fn json_report_records_the_insecure_http_opt_in() {
    let cache = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .args([
            "scan",
            "tests/fixtures/scanner",
            "--format",
            "json",
            "--max-package-depth",
            "0",
            "--allow-insecure-http",
            "--cache",
            cache.path().to_str().unwrap(),
            "--fail-on",
            "critical",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["policy"]["allow_insecure_http"], true);
}

#[test]
fn human_report_is_the_default_format() {
    let cache = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .args([
            "scan",
            "tests/fixtures/scanner",
            "--max-package-depth",
            "0",
            "--cache",
            cache.path().to_str().unwrap(),
            "--fail-on",
            "critical",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = String::from_utf8(output.stdout).unwrap();
    assert!(report.starts_with("chainsec "));
    assert!(report.contains(" source file(s), "));
    assert!(report.contains(" source byte(s), "));
    assert!(!report.trim_start().starts_with('{'));
}

#[test]
fn human_report_filters_below_threshold_unless_verbose() {
    let cache = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .args([
            "scan",
            "tests/fixtures/scanner",
            "--max-package-depth",
            "0",
            "--cache",
            cache.path().to_str().unwrap(),
            "--fail-on",
            "critical",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let report = String::from_utf8(output.stdout).unwrap();
    assert!(!report.contains("High execution:chainsec.py.detection.dynamic-code-execution"));
    assert!(report.contains("Summary\n───────\nCapabilities ("));
    assert!(report.contains("Alerts (0)\n  none"));

    let verbose = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .args([
            "scan",
            "tests/fixtures/scanner",
            "--max-package-depth",
            "0",
            "--cache",
            cache.path().to_str().unwrap(),
            "--fail-on",
            "critical",
            "--verbose",
        ])
        .output()
        .unwrap();

    assert!(verbose.status.success());
    let report = String::from_utf8(verbose.stdout).unwrap();
    assert!(report.contains("execution:chainsec.py.detection.dynamic-code-execution"));
}
#[test]
fn human_report_includes_rule_group_and_dependency() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("sample.py"), "open('/etc/passwd')\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .args([
            "--max-package-depth",
            "0",
            "--cache",
            cache.path().to_str().unwrap(),
            "--format",
            "human",
            "--fail-on",
            "critical",
            "--verbose",
        ])
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("filesystem:chainsec.py.detection.filesystem-open"));
    assert!(stdout.contains("root"));
}
#[test]
fn output_file_contains_analysis_and_leaves_stdout_empty() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let report_file = tempfile::NamedTempFile::new().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .args([
            "--format",
            "json",
            "--max-package-depth",
            "0",
            "--cache",
            cache.path().to_str().unwrap(),
            "--output",
            report_file.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(report_file.path()).unwrap()).unwrap();
    assert_eq!(report["schema_version"], "1.2.0");
}
