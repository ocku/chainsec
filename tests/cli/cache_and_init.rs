use std::process::Command;

#[test]
fn init_creates_a_conservative_root_config_without_scanning() {
    let project = tempfile::tempdir().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .current_dir(project.path())
        .arg("init")
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
    let gitignore = std::fs::read_to_string(project.path().join(".gitignore")).unwrap();
    assert!(
        gitignore
            .lines()
            .any(|line| line.trim() == ".chainsec-cache")
    );

    assert!(config.contains("max_package_depth = 3"));
    assert!(config.contains("# online = true"));
    assert!(config.contains("ignored_paths ="));

    let second = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .current_dir(project.path())
        .arg("init")
        .output()
        .unwrap();
    assert_eq!(second.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&second.stderr).contains("configuration already exists"));
}

#[test]
fn init_gitignore_failure_does_not_leave_config_and_can_be_retried() {
    let project = tempfile::tempdir().unwrap();
    let gitignore = project.path().join(".gitignore");
    let config = project.path().join("chainsec.toml");
    std::fs::write(&gitignore, [0xff]).unwrap();

    let failed = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .current_dir(project.path())
        .arg("init")
        .output()
        .unwrap();

    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stderr).contains("read .gitignore"));
    assert!(!config.exists());
    assert_eq!(std::fs::read(&gitignore).unwrap(), [0xff]);

    std::fs::write(&gitignore, "target/\n").unwrap();
    let retry = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .current_dir(project.path())
        .arg("init")
        .output()
        .unwrap();

    assert!(
        retry.status.success(),
        "{}",
        String::from_utf8_lossy(&retry.stderr)
    );
    assert!(config.is_file());
    assert_eq!(
        std::fs::read_to_string(gitignore).unwrap(),
        "target/\n.chainsec-cache\n"
    );
}

#[test]
fn cache_purge_removes_the_selected_cache_without_scanning() {
    let project = tempfile::tempdir().unwrap();
    let cache = project.path().join("cache");
    std::fs::create_dir_all(cache.join("npm")).unwrap();
    std::fs::write(cache.join("npm/package"), "cached").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .current_dir(project.path())
        .args(["cache", "purge", "--cache", cache.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(cache.is_dir());
    assert!(!cache.join("npm").exists());
    assert!(project.path().join("cache.locks/lifecycle.lock").is_file());
    assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 0);
    assert!(String::from_utf8_lossy(&output.stdout).contains("purged cache"));
}
