use std::{process::Command, sync::atomic::Ordering};

use super::helpers::spawn_npm_registry;

#[test]
fn custom_rule_pack_is_loaded_end_to_end() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let pack = tempfile::NamedTempFile::with_suffix(".json").unwrap();
    std::fs::write(project.path().join("sample.py"), "danger(payload)\n").unwrap();
    std::fs::write(
        project.path().join("package.json"),
        r#"{"name":"fixture","scripts":{"install":"node setup.js"}}"#,
    )
    .unwrap();
    std::fs::write(project.path().join("payload.gz"), [0x1f, 0x8b, 0, 1]).unwrap();
    std::fs::write(
        pack.path(),
        r#"{"rules":[{"id":"CUSTOM001","version":1,"language":"python","finding_type":"arbitrary_code_execution","risk":"high","confidence":"high","rationale":"Custom dangerous call.","remediation":"Remove it.","query":"(call function: (identifier) @callee (#eq? @callee \"danger\")) @match"}]}"#,
    )
    .unwrap();
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
            "--allow-unlocked",
            "--no-default-rules",
            "--rule-pack",
            pack.path().to_str().unwrap(),
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
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["rule_id"], "CUSTOM001");
}

#[test]
fn ignored_rule_selectors_apply_to_generated_install_and_file_findings() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("package.json"),
        r#"{"name":"fixture","scripts":{"install":"node setup.js"}}"#,
    )
    .unwrap();
    std::fs::write(project.path().join("payload.gz"), [0x1f, 0x8b, 0, 1]).unwrap();

    let baseline = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .args([
            "--format",
            "json",
            "--max-package-depth",
            "0",
            "--allow-unlocked",
            "--cache",
            cache.path().to_str().unwrap(),
            "--fail-on",
            "critical",
        ])
        .output()
        .unwrap();
    assert!(
        baseline.status.success(),
        "{}",
        String::from_utf8_lossy(&baseline.stderr)
    );
    let baseline: serde_json::Value = serde_json::from_slice(&baseline.stdout).unwrap();
    let baseline_ids = baseline["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| finding["rule_id"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(
        baseline_ids.contains(&"chainsec.js.detection.manifest.install-hook"),
        "{baseline_ids:?}"
    );
    assert!(
        baseline_ids.contains(&"chainsec.detection.file.compressed"),
        "{baseline_ids:?}"
    );

    let ignored = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .args([
            "--format",
            "json",
            "--max-package-depth",
            "0",
            "--allow-unlocked",
            "--cache",
            cache.path().to_str().unwrap(),
            "--ignore-rule",
            "install:*",
            "--ignore-rule",
            "file:*",
            "--fail-on",
            "high",
        ])
        .output()
        .unwrap();
    assert!(
        ignored.status.success(),
        "{}",
        String::from_utf8_lossy(&ignored.stderr)
    );
    let ignored: serde_json::Value = serde_json::from_slice(&ignored.stdout).unwrap();
    assert!(ignored["findings"].as_array().unwrap().is_empty());
}

#[test]
fn missing_rule_pack_is_invalid_configuration() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let missing_pack = project.path().join("missing-rules.json");

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .args([
            "--no-default-rules",
            "--rule-pack",
            missing_pack.to_str().unwrap(),
            "--cache",
            cache.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("read rule pack"));
}

#[test]
fn dependency_suppression_matches_digest_bearing_findings_and_evidence() {
    let (registry_url, stop, _requests, server) = spawn_npm_registry();
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("chainsec.toml"),
        format!(
            r#"allow_insecure_http = true
max_package_depth = 0
fail_on = "high"

[[suppressions]]
rule = "execution:*"
package = "npm:example@2.0.0"
reason = "Approved test dependency"

[artifactories.npm]
metadata_base_url = {registry_url:?}
"#
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .current_dir(project.path())
        .args([
            "remote",
            "scan",
            "npm:example",
            "--format",
            "json",
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
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let finding = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["rule_id"] == "chainsec.js.detection.dynamic-code-execution")
        .expect("remote fixture should produce an execution finding");
    assert!(
        finding["package"]
            .as_str()
            .unwrap()
            .starts_with("npm:example@2.0.0#")
    );
    assert_eq!(finding["suppressed"], true);

    let evidence = report["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|capability| capability["name"] == "code:dynamic-execution")
        .and_then(|capability| capability["evidence"].as_array())
        .and_then(|evidence| evidence.first())
        .expect("remote fixture should produce dynamic-execution evidence");
    assert!(
        evidence["package"]
            .as_str()
            .unwrap()
            .starts_with("npm:example@2.0.0#")
    );
    assert_eq!(evidence["suppressed"], true);
}

#[test]
fn ignored_rule_is_absent_from_the_report() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("sample.py"), "eval(payload)\n").unwrap();

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
            "--ignore-rule",
            "chainsec.py.detection.dynamic-code-execution",
            "--fail-on",
            "high",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["rule_id"] != "chainsec.py.detection.dynamic-code-execution")
    );
}

#[test]
fn ignore_rule_supports_grouped_globs() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("sample.py"),
        "import requests\nopen('output.txt', 'w')\nrequests.get('https://example.test')\n",
    )
    .unwrap();

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
            "--ignore-rule",
            "network:*",
            "--ignore-rule",
            "filesystem:*",
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
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| {
                finding["finding_type"] != "network_access"
                    && finding["finding_type"] != "filesystem_access"
            })
    );
}

#[test]
fn configured_suppression_is_auditable_and_does_not_fail_the_scan() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("sample.py"), "eval(payload)\n").unwrap();
    std::fs::write(
        project.path().join("chainsec.toml"),
        r#"
max_package_depth = 0
fail_on = "high"

[[suppressions]]
rule = "execution:chainsec.py.detection.dynamic-code-execution"
package = "root"
reason = "The expression is an approved, constrained evaluator."
"#,
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

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let finding = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["rule_id"] == "chainsec.py.detection.dynamic-code-execution")
        .unwrap();
    assert_eq!(finding["suppressed"], true);
    assert_eq!(
        finding["suppression"]["reason"],
        "The expression is an approved, constrained evaluator."
    );
}
#[test]
fn root_config_ignores_rules_and_paths() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::create_dir(project.path().join("tests")).unwrap();
    std::fs::write(project.path().join("sample.py"), "eval(payload)\n").unwrap();
    std::fs::write(
        project.path().join("tests/ignored.py"),
        "open('secret', 'w')\n",
    )
    .unwrap();
    std::fs::write(
        project.path().join("chainsec.toml"),
        "max_package_depth = 0\nignored_rules = [\"execution:chainsec.py.detection.dynamic-code-execution\"]\nignored_paths = [\"tests/*\"]\nfail_on = \"high\"\n",
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

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["findings"].as_array().unwrap().is_empty());
}

#[test]
fn cli_ignores_root_paths() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::create_dir(project.path().join("generated")).unwrap();
    std::fs::write(
        project.path().join("generated/ignored.py"),
        "open('secret', 'w')\n",
    )
    .unwrap();

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
            "--ignore-path",
            "generated/**",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["findings"].as_array().unwrap().is_empty());
}

#[test]
fn root_config_ignores_packages_before_fetching() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("package.json"),
        r#"{"dependencies":{"example":"1.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        project.path().join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{"dependencies":{"example":"1.0.0"}},"node_modules/example":{"version":"1.0.0","resolved":"https://registry.npmjs.org/example/-/example-1.0.0.tgz","integrity":"sha512-ignored"}}}"#,
    )
    .unwrap();
    std::fs::write(
        project.path().join("chainsec.toml"),
        "ignored_packages = [\"npm:example@1.0.0\"]\nfail_on = \"critical\"\n",
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

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["statistics"]["packages"], 1);
    assert!(report["issues"].as_array().unwrap().is_empty());
}
