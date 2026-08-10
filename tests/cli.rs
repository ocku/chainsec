use std::process::Command;

#[test]
fn json_report_has_versioned_contract() {
    let cache = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .args([
            "tests/fixtures/scanner",
            "--format",
            "json",
            "--max-depth",
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
    assert_eq!(report["schema_version"], "1.1.0");
    assert!(report["findings"].as_array().unwrap().len() >= 3);
    assert!(report["capabilities"].is_array());
    assert_eq!(report["statistics"]["packages"], 1);
}

#[test]
fn human_report_is_the_default_format() {
    let cache = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .args([
            "tests/fixtures/scanner",
            "--max-depth",
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
            "tests/fixtures/scanner",
            "--max-depth",
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
            "tests/fixtures/scanner",
            "--max-depth",
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
    assert!(report.contains("High execution:chainsec.py.detection.dynamic-code-execution"));
}

#[test]
fn init_creates_a_conservative_root_config_without_scanning() {
    let project = tempfile::tempdir().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .current_dir(project.path())
        .arg("--init")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.stdout.is_empty());
    let config = std::fs::read_to_string(project.path().join("chainsec.toml")).unwrap();
    assert!(project.path().join(".gitignore").exists());
    assert!(
        std::fs::read_to_string(project.path().join(".gitignore"))
            .unwrap()
            .lines()
            .any(|line| line.trim() == ".chainsec-cache")
    );
    assert!(config.contains("max_depth = 3"));
    assert!(config.contains("# online = true"));
    assert!(config.contains("ignored_paths ="));

    let second = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .current_dir(project.path())
        .arg("--init")
        .output()
        .unwrap();
    assert_eq!(second.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&second.stderr).contains("configuration already exists"));
}

#[test]
fn cache_purge_removes_the_selected_cache_without_scanning() {
    let project = tempfile::tempdir().unwrap();
    let cache = project.path().join("cache");
    std::fs::create_dir_all(cache.join("npm")).unwrap();
    std::fs::write(cache.join("npm/package"), "cached").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .current_dir(project.path())
        .args(["--cache", cache.to_str().unwrap(), "--cache-purge"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!cache.exists());
    assert!(String::from_utf8_lossy(&output.stdout).contains("purged cache"));
}

#[test]
fn global_config_is_complementary_and_repository_config_takes_precedence() {
    let home = tempfile::tempdir().unwrap();
    let global_config = home.path().join(".config/chainsec");
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(&global_config).unwrap();
    std::fs::write(
        global_config.join("config.toml"),
        "format = \"human\"\nignored_rules = [\"execution:*\"]\n",
    )
    .unwrap();
    std::fs::write(project.path().join("sample.py"), "eval(payload)\n").unwrap();
    std::fs::write(
        project.path().join("chainsec.toml"),
        "format = \"json\"\nmax_depth = 0\nfail_on = \"critical\"\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg(project.path())
        .args(["--cache", cache.path().to_str().unwrap()])
        .env("HOME", home.path())
        .env_remove("XDG_CONFIG_HOME")
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
fn xdg_global_config_takes_precedence_over_home_config() {
    let xdg_config_home = tempfile::tempdir().unwrap();
    let xdg_config = xdg_config_home.path().join("chainsec");
    let home = tempfile::tempdir().unwrap();
    let home_config = home.path().join(".config/chainsec");
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(&xdg_config).unwrap();
    std::fs::create_dir_all(&home_config).unwrap();
    std::fs::write(
        xdg_config.join("config.toml"),
        "format = \"json\"\nmax_depth = 0\nfail_on = \"critical\"\n",
    )
    .unwrap();
    std::fs::write(home_config.join("config.toml"), "format = \"human\"\n").unwrap();
    std::fs::write(project.path().join("sample.py"), "print('safe')\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg(project.path())
        .args(["--cache", cache.path().to_str().unwrap()])
        .env("XDG_CONFIG_HOME", xdg_config_home.path())
        .env("HOME", home.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], "1.1.0");
}

#[test]
fn allowed_hosts_extend_across_global_project_and_cli_configuration() {
    let home = tempfile::tempdir().unwrap();
    let global_config = home.path().join(".config/chainsec");
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(&global_config).unwrap();
    std::fs::write(
        global_config.join("config.toml"),
        "online = true\nallowed_hosts = [\"global.example\", \"shared.example\"]\n",
    )
    .unwrap();
    std::fs::write(project.path().join("sample.py"), "print('safe')\n").unwrap();
    std::fs::write(
        project.path().join("chainsec.toml"),
        "max_depth = 0\nfail_on = \"critical\"\nallowed_hosts = [\"project.example\", \"shared.example\"]\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg(project.path())
        .args([
            "--format",
            "json",
            "--cache",
            cache.path().to_str().unwrap(),
            "--allow-host",
            "cli.example",
            "--allow-host",
            "shared.example",
        ])
        .env("HOME", home.path())
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["policy"]["allowed_hosts"],
        serde_json::json!([
            "global.example",
            "shared.example",
            "project.example",
            "cli.example"
        ])
    );
}

#[test]
fn generic_repository_credentials_use_configured_environment_variables() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("sample.py"), "print('safe')\n").unwrap();
    std::fs::write(
        project.path().join("chainsec.toml"),
        r#"
[artifactories.npm]
metadata_base_url = "https://packages.example/npm"

[artifactories.npm.credential]
scope = "https://packages.example/private/"
bearer_token_env = "CHAINSEC_TEST_REGISTRY_TOKEN"
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg(project.path())
        .args([
            "--online",
            "--max-depth",
            "0",
            "--cache",
            cache.path().to_str().unwrap(),
            "--fail-on",
            "critical",
        ])
        .env("CHAINSEC_TEST_REGISTRY_TOKEN", "test-token")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn custom_rule_pack_is_loaded_end_to_end() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let pack = tempfile::NamedTempFile::with_suffix(".json").unwrap();
    std::fs::write(project.path().join("sample.py"), "danger(payload)\n").unwrap();
    std::fs::write(
        pack.path(),
        r#"{"rules":[{"id":"CUSTOM001","version":1,"language":"python","finding_type":"arbitrary_code_execution","risk":"high","confidence":"high","rationale":"Custom dangerous call.","remediation":"Remove it.","query":"(call function: (identifier) @callee (#eq? @callee \"danger\")) @match"}]}"#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg(project.path())
        .args([
            "--format",
            "json",
            "--max-depth",
            "0",
            "--cache",
            cache.path().to_str().unwrap(),
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
    assert_eq!(report["findings"][0]["rule_id"], "CUSTOM001");
}

#[test]
fn ignored_rule_is_absent_from_the_report() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("sample.py"), "eval(payload)\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg(project.path())
        .args([
            "--format",
            "json",
            "--max-depth",
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
        .arg(project.path())
        .args([
            "--format",
            "json",
            "--max-depth",
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
max_depth = 0
fail_on = "high"

[[suppressions]]
rule = "execution:chainsec.py.detection.dynamic-code-execution"
package = "root"
reason = "The expression is an approved, constrained evaluator."
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
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
fn human_report_includes_rule_group_and_dependency() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("sample.py"), "open('/etc/passwd')\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg(project.path())
        .args([
            "--max-depth",
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

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("filesystem:chainsec.py.detection.filesystem-open"));
    assert!(stdout.contains("[root]"));
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
        "max_depth = 0\nignored_rules = [\"execution:chainsec.py.detection.dynamic-code-execution\"]\nignored_paths = [\"tests/*\"]\nfail_on = \"high\"\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
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
        .arg(project.path())
        .args([
            "--format",
            "json",
            "--max-depth",
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
        .arg(project.path())
        .args([
            "--max-depth",
            "0",
            "--max-archive",
            "100m",
            "--max-extracted",
            "100M",
            "--max-source-file",
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
        .arg(project.path())
        .args(["--online", "--max-depth", "0"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn output_file_contains_analysis_and_leaves_stdout_empty() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let report_file = tempfile::NamedTempFile::new().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg(project.path())
        .args([
            "--format",
            "json",
            "--max-depth",
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
    assert_eq!(report["schema_version"], "1.1.0");
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
