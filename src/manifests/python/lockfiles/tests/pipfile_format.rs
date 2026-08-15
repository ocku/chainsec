use super::*;

#[test]
fn pipfile_matching_uses_canonical_names() {
    let (_directory, path) = write_lock(
        "Pipfile.lock",
        &format!(
            r#"{{"default":{{"my-package":{{"version":"==1.2.3","hashes":["sha256:{}"]}}}},"develop":{{}}}}"#,
            "a".repeat(64)
        ),
    );
    let mut dependencies = vec![dependency("My__Package>=1")];
    pipfile::enrich(&path, &mut dependencies).unwrap();
    assert_eq!(dependencies[0].resolved_version.as_deref(), Some("1.2.3"));
    assert_eq!(
        dependencies[0].integrity.as_deref(),
        Some(format!("sha256:{}", "a".repeat(64)).as_str())
    );
}

#[test]
fn pipfile_deduplicates_identical_default_and_develop_records() {
    let hash = format!("sha256:{}", "a".repeat(64));
    let (_directory, path) = write_lock(
        "Pipfile.lock",
        &format!(
            r#"{{"default":{{"demo":{{"version":"==1.2.3","hashes":["{hash}"]}}}},"develop":{{"demo":{{"version":"==1.2.3","hashes":["{hash}"]}}}}}}"#
        ),
    );
    let mut dependencies = vec![dependency("demo>=1")];

    pipfile::enrich(&path, &mut dependencies).unwrap();

    assert_eq!(dependencies[0].resolved_version.as_deref(), Some("1.2.3"));
    assert_eq!(dependencies[0].integrity.as_deref(), Some(hash.as_str()));
}

#[test]
fn pipfile_indexes_large_normalized_name_collision_buckets() {
    let separators = ['-', '_', '.'];
    let mut entries = serde_json::Map::new();
    let mut first_name = String::new();
    for index in 0..1_000usize {
        let mut variant = index;
        let mut name = String::new();
        for (position, character) in "collision".chars().enumerate() {
            name.push(character);
            if position < "collision".len() - 1 {
                name.push(separators[variant % separators.len()]);
                variant /= separators.len();
            }
        }
        if index == 0 {
            first_name.clone_from(&name);
        }
        entries.insert(name, serde_json::json!({"version": format!("=={index}")}));
    }
    let contents = serde_json::json!({"default": entries, "develop": {}}).to_string();
    let (_directory, path) = write_lock("Pipfile.lock", &contents);
    let mut dependencies = vec![dependency(&format!("{first_name}>=10000"))];

    let error = pipfile::enrich(&path, &mut dependencies).unwrap_err();

    assert!(error.to_string().contains("no lock record"));
}

#[test]
fn malformed_unconstrained_pipfile_version_is_rejected() {
    let (_directory, path) = write_lock(
        "Pipfile.lock",
        r#"{"default":{"demo":{"version":"not-a-version"}},"develop":{}}"#,
    );
    let mut dependencies = vec![dependency("demo")];

    assert!(pipfile::enrich(&path, &mut dependencies).is_err());
}

#[test]
fn pipfile_does_not_resolve_hashless_direct_url_or_vcs_dependencies() {
    for requirement in [
        "demo @ https://artifacts.example.test/demo.tar.gz",
        "demo @ git+https://git.example.test/demo.git@0123456789abcdef0123456789abcdef01234567",
    ] {
        let source = requirement.split_once('@').unwrap().1.trim();
        let (_directory, path) = write_lock(
            "Pipfile.lock",
            &format!(
                r#"{{"default":{{"demo":{{"version":"==1","file":"{source}"}}}},"develop":{{}}}}"#
            ),
        );
        let mut dependencies = vec![dependency(requirement)];
        pipfile::enrich(&path, &mut dependencies).unwrap();

        assert!(dependencies[0].resolved_version.is_none());
        assert!(dependencies[0].integrity.is_none());
        assert!(!dependencies[0].registry_integrity_required);
        assert!(!dependencies[0].is_resolved());
    }
}

#[test]
fn pipfile_expands_multiple_authorized_hashes() {
    let first = "1".repeat(64);
    let second = "2".repeat(64);
    let (_directory, path) = write_lock(
        "Pipfile.lock",
        &format!(
            r#"{{"default":{{"demo":{{"version":"==1","hashes":["sha256:{first}","sha256:{second}"]}}}},"develop":{{}}}}"#
        ),
    );
    let mut dependencies = vec![dependency("demo==1")];
    pipfile::enrich(&path, &mut dependencies).unwrap();
    assert_eq!(dependencies.len(), 2);
    assert_eq!(
        dependencies[0].integrity.as_deref(),
        Some(format!("sha256:{first}").as_str())
    );
    assert_eq!(
        dependencies[1].integrity.as_deref(),
        Some(format!("sha256:{second}").as_str())
    );
}

#[test]
fn pipfile_empty_hashes_require_registry_integrity() {
    let (_directory, path) = write_lock(
        "Pipfile.lock",
        r#"{"default":{"demo":{"version":"==1","hashes":[]}},"develop":{}}"#,
    );
    let mut dependencies = vec![dependency("demo==1")];
    pipfile::enrich(&path, &mut dependencies).unwrap();
    assert!(dependencies[0].requires_registry_integrity());
}
