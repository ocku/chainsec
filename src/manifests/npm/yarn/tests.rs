use std::fs;

use crate::model::Ecosystem;

use super::*;

fn enrich_fixture(lockfile: &str, name: &str, requirement: &str) -> Dependency {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("yarn.lock");
    fs::write(&path, lockfile).unwrap();
    let mut dependencies = [Dependency::declared(Ecosystem::Npm, name, requirement)];
    enrich(&path, &mut dependencies).unwrap();
    dependencies.into_iter().next().unwrap()
}

#[test]
fn classic_resolved_digest_fragment_is_not_accepted_as_integrity() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("yarn.lock");
    fs::write(
        &path,
        r#"
example@^1.0.0:
  version "1.2.3"
  resolved "https://registry.example.test/example.tgz#000102030405060708090a0b0c0d0e0f10111213"
"#,
    )
    .unwrap();
    let mut dependencies = [Dependency::declared(Ecosystem::Npm, "example", "^1.0.0")];

    enrich(&path, &mut dependencies).unwrap();

    assert!(dependencies[0].integrity.is_none());
    assert_eq!(
        dependencies[0].source_url.as_deref(),
        Some("https://registry.example.test/example.tgz")
    );
}

#[test]
fn selector_with_a_comma_in_its_url_is_indexed_whole() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("yarn.lock");
    fs::write(
        &path,
        r#"
"example@https://packages.example.test/example,a.tgz":
  version "1.2.3"
  resolved "https://packages.example.test/example,a.tgz#000102030405060708090a0b0c0d0e0f10111213"
"#,
    )
    .unwrap();
    let mut dependencies = [Dependency::declared(
        Ecosystem::Npm,
        "example",
        "https://packages.example.test/example,a.tgz",
    )];

    enrich(&path, &mut dependencies).unwrap();

    assert_eq!(dependencies[0].resolved_version.as_deref(), Some("1.2.3"));
    assert_eq!(
        dependencies[0].source_url.as_deref(),
        Some("https://packages.example.test/example,a.tgz")
    );
}

#[test]
fn combined_selector_key_indexes_each_selector() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("yarn.lock");
    fs::write(
        &path,
        r#"
"example@^1.0.0, example@~1.2.0":
  version "1.2.3"
  resolved "https://registry.example.test/example.tgz#000102030405060708090a0b0c0d0e0f10111213"
"#,
    )
    .unwrap();
    let mut dependencies = [Dependency::declared(Ecosystem::Npm, "example", "~1.2.0")];

    enrich(&path, &mut dependencies).unwrap();

    assert_eq!(dependencies[0].resolved_version.as_deref(), Some("1.2.3"));
}

#[test]
fn incompatible_locked_version_does_not_enrich_dependency() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("yarn.lock");
    fs::write(
        &path,
        r#"
target@^1.0.0:
  version "9.0.0"
  resolved "https://registry.example.test/target.tgz"
  integrity sha512-target
"#,
    )
    .unwrap();
    let mut dependencies = [Dependency::declared(Ecosystem::Npm, "target", "^1.0.0")];

    enrich(&path, &mut dependencies).unwrap();

    assert!(dependencies[0].resolved_version.is_none());
    assert!(dependencies[0].integrity.is_none());
    assert!(dependencies[0].lockfile.is_none());
}

#[test]
fn pinned_github_archive_requires_a_matching_codeload_resolution() {
    let requirement = "github:owner/repository#0123456789012345678901234567890123456789";
    for resolved in [
        "https://registry.example.test/child.tgz",
        "https://codeload.github.com/owner/repository/tar.gz/1111111111111111111111111111111111111111",
        "https://codeload.github.com/other/repository/tar.gz/0123456789012345678901234567890123456789",
    ] {
        let dependency = enrich_fixture(
            &format!(
                r#"
"child@{requirement}":
  version "1.0.0"
  resolved "{resolved}"
"#
            ),
            "child",
            requirement,
        );
        assert!(dependency.resolved_version.is_none(), "{resolved}");
        assert!(dependency.source_url.is_none(), "{resolved}");
        assert!(dependency.lockfile.is_none(), "{resolved}");
    }

    let dependency = enrich_fixture(
        &format!(
            r#"
"child@{requirement}":
  version "1.0.0"
  resolved "https://codeload.github.com/owner/repository/tar.gz/0123456789012345678901234567890123456789"
"#
        ),
        "child",
        requirement,
    );
    assert_eq!(
        dependency.resolved_version.as_deref(),
        Some("0123456789012345678901234567890123456789")
    );
    assert!(dependency.lockfile.is_some());
}

#[test]
fn berry_workspace_resolution_becomes_a_local_file_source() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("yarn.lock");
    fs::write(
        &path,
        r#"
__metadata:
  version: 8

"workspace-child@workspace:packages/child":
  version: 0.0.0-use.local
  resolution: "workspace-child@workspace:packages/child"
  linkType: soft
"#,
    )
    .unwrap();
    let mut dependencies = [Dependency::declared(
        Ecosystem::Npm,
        "workspace-child",
        "workspace:packages/child",
    )];

    enrich(&path, &mut dependencies).unwrap();

    assert!(
        dependencies[0]
            .source_url
            .as_deref()
            .is_some_and(|url| { url.starts_with("file://") && url.ends_with("/packages/child") })
    );
    assert!(dependencies[0].is_local());
    assert!(dependencies[0].lockfile.is_some());
}

#[test]
fn rejects_unknown_or_malformed_berry_versions() {
    for metadata in ["version: 99", "version: future"] {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("yarn.lock");
        fs::write(
            &path,
            format!("__metadata:\n  {metadata}\n\n\"example@npm:^1\":\n  version: 1.0.0\n"),
        )
        .unwrap();
        let mut dependencies = [Dependency::declared(Ecosystem::Npm, "example", "^1")];
        assert!(enrich(&path, &mut dependencies).is_err());
    }
}

#[test]
fn valid_scoped_and_unscoped_registry_aliases_are_enriched() {
    for (target, integrity) in [
        ("target", "sha512-unscoped"),
        ("@scope/target", "sha512-scoped"),
    ] {
        let dependency = enrich_fixture(
            &format!(
                r#"
__metadata:
  version: 8

"alias@npm:{target}@^2":
  version: 2.3.0
  resolution: "{target}@npm:2.3.0"
  integrity: {integrity}
"#
            ),
            "alias",
            &format!("npm:{target}@^2"),
        );

        assert_eq!(dependency.resolved_version.as_deref(), Some("2.3.0"));
        assert_eq!(dependency.integrity.as_deref(), Some(integrity));
        assert!(dependency.lockfile.is_some());
    }
}

#[test]
fn mismatched_scoped_and_unscoped_registry_alias_targets_stay_unresolved() {
    for (declared, locked) in [("target", "other"), ("@scope/target", "@scope/other")] {
        let dependency = enrich_fixture(
            &format!(
                r#"
__metadata:
  version: 8

"alias@npm:{declared}@^2":
  version: 2.3.0
  resolution: "{locked}@npm:2.3.0"
  integrity: sha512-wrong
"#
            ),
            "alias",
            &format!("npm:{declared}@^2"),
        );

        assert!(dependency.resolved_version.is_none());
        assert!(dependency.integrity.is_none());
        assert!(dependency.lockfile.is_none());
    }
}

#[test]
fn out_of_range_registry_alias_stays_unresolved() {
    let dependency = enrich_fixture(
        r#"
__metadata:
  version: 8

"alias@npm:target@^2":
  version: 3.0.0
  resolution: "target@npm:3.0.0"
  integrity: sha512-wrong
"#,
        "alias",
        "npm:target@^2",
    );

    assert!(dependency.resolved_version.is_none());
    assert!(dependency.integrity.is_none());
    assert!(dependency.lockfile.is_none());
}

#[test]
fn malformed_registry_alias_stays_unresolved() {
    let dependency = enrich_fixture(
        r#"
__metadata:
  version: 8

"alias@npm:target":
  version: 2.3.0
  resolution: "target@npm:2.3.0"
  integrity: sha512-wrong
"#,
        "alias",
        "npm:target",
    );

    assert!(dependency.resolved_version.is_none());
    assert!(dependency.lockfile.is_none());
}
