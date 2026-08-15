use std::process::Command;

#[test]
fn missing_scan_root_is_invalid_input() {
    let parent = tempfile::tempdir().unwrap();
    let missing = parent.path().join("does-not-exist");

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(&missing)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("resolve project directory"));
}

#[test]
fn install_script_priorities_distinguish_npm_and_python() {
    let npm = tempfile::tempdir().unwrap();
    let npm_cache = tempfile::tempdir().unwrap();
    std::fs::write(
        npm.path().join("package.json"),
        r#"{"name":"fixture","scripts":{"install":"node setup.js"}}"#,
    )
    .unwrap();
    let npm_output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(npm.path())
        .args([
            "--format",
            "json",
            "--allow-unlocked",
            "--cache",
            npm_cache.path().to_str().unwrap(),
            "--fail-on",
            "high",
        ])
        .output()
        .unwrap();
    assert_eq!(npm_output.status.code(), Some(1));
    let npm_report: serde_json::Value = serde_json::from_slice(&npm_output.stdout).unwrap();
    assert_eq!(
        npm_report["findings"][0]["rule_id"],
        "chainsec.js.detection.manifest.install-hook"
    );
    assert_eq!(npm_report["findings"][0]["risk"], "high");

    let python = tempfile::tempdir().unwrap();
    let python_cache = tempfile::tempdir().unwrap();
    std::fs::write(python.path().join("setup.py"), "print('install')\n").unwrap();
    let python_output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(python.path())
        .args([
            "--format",
            "json",
            "--allow-unlocked",
            "--cache",
            python_cache.path().to_str().unwrap(),
            "--fail-on",
            "high",
        ])
        .output()
        .unwrap();
    assert!(
        python_output.status.success(),
        "{}",
        String::from_utf8_lossy(&python_output.stderr)
    );
    let python_report: serde_json::Value = serde_json::from_slice(&python_output.stdout).unwrap();
    assert_eq!(
        python_report["findings"][0]["rule_id"],
        "chainsec.py.detection.manifest.install-hook"
    );
    assert_eq!(python_report["findings"][0]["risk"], "medium");
}

#[test]
fn unsupported_artifact_scheme_uses_policy_exit_code() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("package.json"),
        r#"{"dependencies":{"example":"1.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        project.path().join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{"dependencies":{"example":"1.0.0"}},"node_modules/example":{"version":"1.0.0","resolved":"ftp://packages.example.test/example.tgz","integrity":"sha512-ignored"}}}"#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .args([
            "--format",
            "json",
            "--online",
            "--allow-host",
            "packages.example.test",
            "--cache",
            cache.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue["code"] == "policy_error")
    );
}

#[test]
fn offline_flag_is_not_available() {
    let project = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .arg("--offline")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected argument '--offline'"));
}

#[test]
fn human_formatted_size_limits_are_accepted() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .args([
            "--max-package-depth",
            "0",
            "--max-archive-size",
            "100m",
            "--max-extracted-size",
            "100M",
            "--max-source-file-size",
            "100MiB",
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
}

#[test]
fn online_without_allowlist_allows_local_only_scans() {
    let project = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .args(["--online", "--max-package-depth", "0"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn unlocked_dependency_uses_policy_exit_code() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("package.json"),
        r#"{"dependencies":{"example":"^1"}}"#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .args([
            "--format",
            "json",
            "--cache",
            cache.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue["code"] == "policy_error")
    );
}
