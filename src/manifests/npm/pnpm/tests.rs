use std::fs;

use crate::model::Ecosystem;

use super::*;

fn enrich_fixture(lockfile: &str, name: &str, requirement: &str) -> Dependency {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("pnpm-lock.yaml");
    fs::write(&path, lockfile).unwrap();
    let mut dependencies = [Dependency::declared(Ecosystem::Npm, name, requirement)];
    enrich(&path, &mut dependencies).unwrap();
    dependencies.into_iter().next().unwrap()
}

#[test]
fn enriches_development_dependency() {
    let dependency = enrich_fixture(
        r#"
lockfileVersion: '9.0'
importers:
  .:
    devDependencies:
      child:
        specifier: ^2
        version: 2.1.0
packages:
  child@2.1.0:
    resolution:
      integrity: sha512-child
"#,
        "child",
        "^2",
    );

    assert_eq!(dependency.resolved_version.as_deref(), Some("2.1.0"));
    assert_eq!(dependency.integrity.as_deref(), Some("sha512-child"));
    assert!(dependency.lockfile.is_some());
}

#[test]
fn registry_alias_uses_target_package_and_version_without_becoming_local() {
    let dependency = enrich_fixture(
        r#"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      alias:
        specifier: npm:@scope/target@^2
        version: npm:@scope/target@2.3.0
packages:
  '@scope/target@2.3.0':
    resolution:
      integrity: sha512-target
"#,
        "alias",
        "npm:@scope/target@^2",
    );

    assert_eq!(dependency.name, "alias");
    assert_eq!(dependency.requirement, "npm:@scope/target@^2");
    assert_eq!(dependency.resolved_version.as_deref(), Some("2.3.0"));
    assert_eq!(dependency.integrity.as_deref(), Some("sha512-target"));
    assert!(dependency.source_url.is_none());
    assert!(!dependency.is_local());
}

#[test]
fn unscoped_registry_alias_uses_target_package_and_version() {
    let dependency = enrich_fixture(
        r#"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      alias:
        specifier: npm:target@^2
        version: npm:target@2.3.0
packages:
  target@2.3.0:
    resolution:
      integrity: sha512-target
"#,
        "alias",
        "npm:target@^2",
    );

    assert_eq!(dependency.resolved_version.as_deref(), Some("2.3.0"));
    assert_eq!(dependency.integrity.as_deref(), Some("sha512-target"));
    assert!(dependency.lockfile.is_some());
}

#[test]
fn mismatched_scoped_and_unscoped_registry_alias_targets_stay_unresolved() {
    for (declared, locked) in [("target", "other"), ("@scope/target", "@scope/other")] {
        let dependency = enrich_fixture(
            &format!(
                r#"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      alias:
        specifier: npm:{declared}@^2
        version: npm:{locked}@2.3.0
packages:
  '{locked}@2.3.0':
    resolution:
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
fn malformed_locked_registry_alias_stays_unresolved() {
    let dependency = enrich_fixture(
        r#"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      alias:
        specifier: npm:target@^2
        version: npm:target
packages:
  target@2.3.0:
    resolution:
      integrity: sha512-wrong
"#,
        "alias",
        "npm:target@^2",
    );

    assert!(dependency.resolved_version.is_none());
    assert!(dependency.lockfile.is_none());
}

#[test]
fn malformed_declared_registry_alias_range_stays_unresolved() {
    let dependency = enrich_fixture(
        r#"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      alias:
        specifier: npm:target@not-a-range
        version: npm:target@2.3.0
packages:
  target@2.3.0:
    resolution:
      integrity: sha512-wrong
"#,
        "alias",
        "npm:target@not-a-range",
    );

    assert!(dependency.resolved_version.is_none());
    assert!(dependency.lockfile.is_none());
}

#[test]
fn version_six_peer_qualified_reference_uses_the_full_package_key() {
    let dependency = enrich_fixture(
        r#"
lockfileVersion: '6.0'
importers:
  .:
    dependencies:
      react-dom:
        specifier: ^18
        version: 18.2.0(react@18.2.0)
packages:
  /react-dom@18.2.0(react@18.2.0):
    resolution:
      integrity: sha512-react-dom
"#,
        "react-dom",
        "^18",
    );

    assert_eq!(dependency.resolved_version.as_deref(), Some("18.2.0"));
    assert_eq!(dependency.integrity.as_deref(), Some("sha512-react-dom"));
    assert!(dependency.lockfile.is_some());
}

#[test]
fn incompatible_locked_version_does_not_enrich_dependency() {
    let dependency = enrich_fixture(
        r#"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      target:
        specifier: ^1.0.0
        version: 9.0.0
packages:
  target@9.0.0:
    resolution:
      integrity: sha512-target
"#,
        "target",
        "^1.0.0",
    );

    assert!(dependency.resolved_version.is_none());
    assert!(dependency.integrity.is_none());
    assert!(dependency.lockfile.is_none());
}

#[test]
fn pinned_github_archive_requires_a_matching_codeload_reference() {
    let requirement = "github:owner/repository#0123456789012345678901234567890123456789";
    for version in [
        "1.0.0",
        "https://codeload.github.com/owner/repository/tar.gz/1111111111111111111111111111111111111111",
        "https://codeload.github.com/other/repository/tar.gz/0123456789012345678901234567890123456789",
    ] {
        let dependency = enrich_fixture(
            &format!(
                r#"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      child:
        specifier: {requirement}
        version: {version}
packages: {{}}
"#
            ),
            "child",
            requirement,
        );
        assert!(dependency.resolved_version.is_none(), "{version}");
        assert!(dependency.source_url.is_none(), "{version}");
        assert!(dependency.lockfile.is_none(), "{version}");
    }

    let dependency = enrich_fixture(
        &format!(
            r#"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      child:
        specifier: {requirement}
        version: https://codeload.github.com/owner/repository/tar.gz/0123456789012345678901234567890123456789
packages: {{}}
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
fn concrete_link_reference_becomes_a_local_file_source() {
    let dependency = enrich_fixture(
        r#"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      workspace-child:
        specifier: workspace:*
        version: link:packages/child
packages: {}
"#,
        "workspace-child",
        "workspace:*",
    );

    assert!(
        dependency
            .source_url
            .as_deref()
            .is_some_and(|url| { url.starts_with("file://") && url.ends_with("/packages/child") })
    );
    assert!(dependency.is_local());
    assert!(dependency.lockfile.is_some());
}

#[test]
fn wildcard_workspace_reference_without_a_path_stays_unresolved() {
    let dependency = enrich_fixture(
        r#"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      workspace-child:
        specifier: workspace:*
        version: workspace:*
packages: {}
"#,
        "workspace-child",
        "workspace:*",
    );

    assert!(dependency.source_url.is_none());
    assert!(dependency.lockfile.is_none());
}

#[test]
fn registry_package_without_explicit_tarball_does_not_assume_npmjs() {
    let dependency = enrich_fixture(
        r#"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      target:
        specifier: 1.0.0
        version: 1.0.0
packages:
  target@1.0.0:
    resolution:
      integrity: sha512-target
"#,
        "target",
        "1.0.0",
    );

    assert_eq!(dependency.resolved_version.as_deref(), Some("1.0.0"));
    assert!(dependency.source_url.is_none());
    assert_eq!(dependency.integrity.as_deref(), Some("sha512-target"));
}

#[test]
fn exact_registry_version_without_integrity_defers_to_registry_metadata() {
    let dependency = enrich_fixture(
        r#"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      target:
        specifier: 1.0.0
        version: 1.0.0
packages:
  target@1.0.0:
    resolution: {}
"#,
        "target",
        "1.0.0",
    );

    assert_eq!(dependency.resolved_version.as_deref(), Some("1.0.0"));
    assert!(dependency.integrity.is_none());
    assert!(dependency.source_url.is_none());
    assert!(dependency.registry_integrity_required);
}
