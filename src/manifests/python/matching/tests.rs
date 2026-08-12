use super::*;
use crate::model::Ecosystem;

#[test]
fn direct_url_requires_matching_lock_source_metadata() {
    let mut dependency = Dependency::declared(
        Ecosystem::Python,
        "demo",
        "demo @ https://artifacts.example.test/demo.tar.gz",
    );
    dependency.source_url = Some("https://artifacts.example.test/demo.tar.gz".to_owned());
    let without_source: TomlValue = toml::from_str("name = 'demo'\nversion = '1'").unwrap();
    let matching: TomlValue = toml::from_str(
        "name = 'demo'\nversion = '1'\nurl = 'https://artifacts.example.test/demo.tar.gz'",
    )
    .unwrap();

    let wrong_source: TomlValue = toml::from_str(
        "name = 'demo'\nversion = '1'\nurl = 'https://mirror.example.test/demo.tar.gz'",
    )
    .unwrap();

    assert!(!toml_source_compatible(&dependency, &without_source));
    assert!(!toml_source_compatible(&dependency, &wrong_source));
    assert!(toml_source_compatible(&dependency, &matching));
}

#[test]
fn toml_git_and_directory_sources_require_matching_immutable_identities() {
    let revision = "0123456789abcdef0123456789abcdef01234567";
    let mut git = Dependency::declared(
        Ecosystem::Python,
        "demo",
        "demo @ git+https://git.example.test/demo.git@0123456789abcdef0123456789abcdef01234567",
    );
    git.source_url = Some(format!("git+https://git.example.test/demo.git@{revision}"));
    let matching_git: TomlValue = toml::from_str(&format!(
        "name = 'demo'\nversion = '1'\nsource = {{type = 'git', url = 'https://git.example.test/demo.git', resolved_reference = '{revision}'}}"
    ))
    .unwrap();
    let mutable_git: TomlValue = toml::from_str(
        "name = 'demo'\nversion = '1'\nsource = {type = 'git', url = 'https://git.example.test/demo.git', resolved_reference = 'main'}",
    )
    .unwrap();
    let wrong_git: TomlValue = toml::from_str(&format!(
        "name = 'demo'\nversion = '1'\nsource = {{type = 'git', url = 'https://git.example.test/demo.git', resolved_reference = '{}'}}",
        "f".repeat(40)
    ))
    .unwrap();

    let mut directory = Dependency::declared(Ecosystem::Python, "local-demo", "file:../demo");
    directory.source_url = Some("file:../demo".to_owned());
    let matching_directory: TomlValue = toml::from_str(
        "name = 'local-demo'\nversion = '1'\nsource = {type = 'directory', directory = '../demo'}",
    )
    .unwrap();
    let wrong_directory: TomlValue = toml::from_str(
        "name = 'local-demo'\nversion = '1'\nsource = {type = 'directory', directory = '../other'}",
    )
    .unwrap();

    assert!(toml_source_compatible(&git, &matching_git));
    assert!(!toml_source_compatible(&git, &mutable_git));
    assert!(!toml_source_compatible(&git, &wrong_git));
    assert!(toml_source_compatible(&directory, &matching_directory));
    assert!(!toml_source_compatible(&directory, &wrong_directory));
}

#[test]
fn malformed_constraints_fail_closed() {
    let dependency = Dependency::declared(Ecosystem::Python, "demo", "demo=>1");
    let package: TomlValue = toml::from_str("name = 'demo'\nversion = '9'").unwrap();
    let packages = vec![package];
    let index = index_toml_packages(&packages);

    let error = find_package(Path::new("lock"), &index, &dependency).unwrap_err();
    assert!(error.to_string().contains("invalid version constraint"));
}

#[test]
fn malformed_unconstrained_toml_lock_version_is_rejected() {
    let dependency = Dependency::declared(Ecosystem::Python, "demo", "demo");
    let package: TomlValue = toml::from_str("name = 'demo'\nversion = 'not-a-version'").unwrap();
    let packages = vec![package];
    let index = index_toml_packages(&packages);

    let error = find_package(Path::new("lock"), &index, &dependency).unwrap_err();
    assert!(error.to_string().contains("no lock record"));
}

#[test]
fn malformed_unconstrained_json_lock_version_is_rejected() {
    let dependency = Dependency::declared(Ecosystem::Python, "demo", "demo");
    let package: JsonValue = serde_json::json!({
        "name": "demo",
        "version": "not-a-version"
    });
    let packages = [package];
    let mut index = JsonPackageIndex::new();
    index.insert("demo".to_owned(), packages.iter().collect());

    let error = find_json_package(Path::new("lock"), &index, &dependency).unwrap_err();
    assert!(error.to_string().contains("no lock record"));
}

#[test]
fn pipfile_direct_source_requires_matching_identity() {
    let mut dependency = Dependency::declared(
        Ecosystem::Python,
        "demo",
        "demo @ git+https://git.example.test/demo.git@0123456789abcdef0123456789abcdef01234567",
    );
    dependency.source_url = Some(
        "git+https://git.example.test/demo.git@0123456789abcdef0123456789abcdef01234567".to_owned(),
    );
    let without_source: JsonValue = serde_json::from_str(r#"{"version":"==1"}"#).unwrap();
    let wrong_source: JsonValue =
        serde_json::from_str(r#"{"version":"==1","git":"https://git.example.test/other.git"}"#)
            .unwrap();
    let missing_ref: JsonValue =
        serde_json::from_str(r#"{"version":"==1","git":"https://git.example.test/demo.git"}"#)
            .unwrap();
    let matching: JsonValue = serde_json::from_str(
        r#"{"version":"==1","git":"https://git.example.test/demo.git","ref":"0123456789abcdef0123456789abcdef01234567"}"#,
    )
    .unwrap();

    let source_prefix_attack: JsonValue = serde_json::from_str(
        r#"{"version":"==1","git":"https://git.example.test/demo","ref":"0123456789abcdef0123456789abcdef01234567"}"#,
    )
    .unwrap();
    let revision_substring_attack: JsonValue = serde_json::from_str(
        r#"{"version":"==1","git":"https://git.example.test/demo.git","ref":"123456789abcdef0123456789abcdef0123456"}"#,
    )
    .unwrap();
    let canonical_matching: JsonValue = serde_json::from_str(
        r#"{"version":"==1","git":"https://git.example.test:443/demo.git","ref":"0123456789ABCDEF0123456789ABCDEF01234567"}"#,
    )
    .unwrap();

    assert!(!json_source_compatible(&dependency, &without_source));
    assert!(!json_source_compatible(&dependency, &wrong_source));
    assert!(!json_source_compatible(&dependency, &missing_ref));
    assert!(!json_source_compatible(&dependency, &source_prefix_attack));
    assert!(!json_source_compatible(
        &dependency,
        &revision_substring_attack
    ));
    assert!(json_source_compatible(&dependency, &matching));
    assert!(json_source_compatible(&dependency, &canonical_matching));
}
