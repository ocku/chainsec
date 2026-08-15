use std::process::Command;

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
        "format = \"json\"\nmax_package_depth = 0\nfail_on = \"critical\"\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
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
        "format = \"json\"\nmax_package_depth = 0\nfail_on = \"critical\"\n",
    )
    .unwrap();
    std::fs::write(home_config.join("config.toml"), "format = \"human\"\n").unwrap();
    std::fs::write(project.path().join("sample.py"), "print('safe')\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
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
    assert_eq!(report["schema_version"], "1.2.0");
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
        "max_package_depth = 0\nfail_on = \"critical\"\nallowed_hosts = [\"project.example\", \"shared.example\"]\n",
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
        .arg("scan")
        .arg(project.path())
        .args([
            "--online",
            "--max-package-depth",
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
