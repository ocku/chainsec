use std::{
    process::Command,
    sync::{Arc, atomic::Ordering},
};

use super::helpers::{spawn_failing_npm_registry, spawn_npm_registry};

#[test]
fn remote_diff_validates_format_and_version_history_before_network_access() {
    let cache = tempfile::tempdir().unwrap();
    let sarif = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .args([
            "remote",
            "diff",
            "npm:express",
            "--last",
            "2",
            "--format",
            "sarif",
            "--cache",
            cache.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(sarif.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&sarif.stderr);
    assert!(
        stderr.contains("support only human and JSON output"),
        "{stderr}"
    );

    let revision = "0123456789012345678901234567890123456789";
    let github = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .args([
            "remote",
            "scan",
            &format!("github:owner/repository@{revision}"),
            "--diff",
            "2",
            "--cache",
            cache.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(github.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&github.stderr)
            .contains("GitHub dependencies have no registry version history")
    );
}

#[test]
fn remote_diff_count_must_provide_a_baseline() {
    for count in ["0", "1"] {
        let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
            .args(["remote", "scan", "npm:express", "--diff", count])
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("must be at least 2"));
    }
}

fn run_registry_diff(arguments: &[&str]) -> (serde_json::Value, Vec<String>) {
    let (registry_url, stop, requests, server) = spawn_npm_registry();
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("chainsec.toml"),
        format!(
            "allow_insecure_http = true\n\n[artifactories.npm]\nmetadata_base_url = {registry_url:?}\n"
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .current_dir(project.path())
        .args(arguments)
        .args([
            "--format",
            "json",
            "--max-package-depth",
            "0",
            "--fail-on",
            "critical",
            "--cache",
            cache.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let requests = Arc::try_unwrap(requests).unwrap().into_inner().unwrap();
    (serde_json::from_slice(&output.stdout).unwrap(), requests)
}

fn assert_diff_versions(
    report: &serde_json::Value,
    versions: &[&str],
    comparisons: &[(&str, &str)],
) {
    assert_eq!(report["schema_version"], "1.0.0");
    assert_eq!(report["report_type"], "version_diff");
    assert_eq!(report["resolved_version"], versions[0]);
    assert_eq!(report["versions"], serde_json::json!(versions));

    let diffs = report["diffs"].as_array().unwrap();
    assert_eq!(diffs.len(), comparisons.len());
    for (diff, (from, to)) in diffs.iter().zip(comparisons) {
        assert_eq!(diff["from_version"], *from);
        assert_eq!(diff["to_version"], *to);
    }
}

fn assert_requested_archives(requests: &[String], expected: &[&str]) {
    let mut actual = requests
        .iter()
        .filter(|request| request.ends_with(".tgz"))
        .map(String::as_str)
        .collect::<Vec<_>>();
    let mut expected = expected.to_vec();
    actual.sort_unstable();
    expected.sort_unstable();
    assert_eq!(actual, expected);
}

#[test]
fn remote_scan_diff_convenience_uses_newest_and_immediate_predecessor() {
    let (report, requests) = run_registry_diff(&["remote", "scan", "npm:example", "--diff", "2"]);

    assert_diff_versions(&report, &["2.0.0", "1.5.0"], &[("1.5.0", "2.0.0")]);
    assert_requested_archives(&requests, &["/example-1.5.0.tgz", "/example-2.0.0.tgz"]);
    assert!(
        report["diffs"][0]["detections"]["added"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["rule_id"] == "chainsec.js.detection.dynamic-code-execution")
    );
    assert!(
        report["diffs"][0]["capabilities"]["added"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["name"] == "code:dynamic-execution")
    );
}

#[test]
fn remote_diff_compare_scans_only_exact_endpoints() {
    let (report, requests) = run_registry_diff(&[
        "remote",
        "diff",
        "npm:example",
        "--compare",
        "1.0.0",
        "2.0.0",
    ]);

    assert_diff_versions(&report, &["2.0.0", "1.0.0"], &[("1.0.0", "2.0.0")]);
    assert_requested_archives(&requests, &["/example-1.0.0.tgz", "/example-2.0.0.tgz"]);
}

#[test]
fn remote_diff_range_scans_inclusive_versions_and_compares_adjacent_releases() {
    let (report, requests) =
        run_registry_diff(&["remote", "diff", "npm:example", "--range", "1.0.0", "2.0.0"]);

    assert_diff_versions(
        &report,
        &["2.0.0", "1.5.0", "1.0.0"],
        &[("1.5.0", "2.0.0"), ("1.0.0", "1.5.0")],
    );
    assert_requested_archives(
        &requests,
        &[
            "/example-1.0.0.tgz",
            "/example-1.5.0.tgz",
            "/example-2.0.0.tgz",
        ],
    );
}

#[test]
fn remote_diff_stops_downloading_after_a_root_failure() {
    let (registry_url, stop, requests, server) = spawn_failing_npm_registry();
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("chainsec.toml"),
        format!(
            "allow_insecure_http = true\n\n[artifactories.npm]\nmetadata_base_url = {registry_url:?}\n"
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .current_dir(project.path())
        .args([
            "remote",
            "diff",
            "npm:example",
            "--last",
            "3",
            "--threads",
            "1",
            "--cache",
            cache.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    assert_eq!(output.status.code(), Some(3));
    let requests = Arc::try_unwrap(requests).unwrap().into_inner().unwrap();
    assert_requested_archives(&requests, &["/example-2.0.0.tgz"]);
}

#[test]
fn remote_diff_rejects_too_many_roots_before_downloading_archives() {
    let (registry_url, stop, requests, server) = spawn_npm_registry();
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("chainsec.toml"),
        format!(
            "allow_insecure_http = true\n\n[artifactories.npm]\nmetadata_base_url = {registry_url:?}\n"
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .current_dir(project.path())
        .args([
            "remote",
            "diff",
            "npm:example",
            "--range",
            "1.0.0",
            "2.0.0",
            "--max-packages",
            "2",
            "--cache",
            cache.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    assert_eq!(output.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("remote version candidates"),
        "stderr: {stderr}"
    );
    let requests = Arc::try_unwrap(requests).unwrap().into_inner().unwrap();
    assert_requested_archives(&requests, &[]);
}
