use std::fs;

use super::super::discover_with_contexts;
use crate::manifests::NpmLockContext;

#[test]
fn malformed_lockfile_keeps_declared_dependencies_visible() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"dependencies":{"example":"^1"}}"#,
    )
    .unwrap();
    fs::write(root.path().join("package-lock.json"), "{").unwrap();

    let outcome = discover_with_contexts(root.path(), &[], &[]);

    assert_eq!(outcome.errors.len(), 1);
    assert_eq!(outcome.discovery.dependencies.len(), 1);
    assert_eq!(outcome.discovery.dependencies[0].name, "example");
    assert!(outcome.discovery.dependencies[0].lockfile.is_none());
}

#[test]
fn npm_workspace_member_local_dependency_retains_its_declaration_directory_without_a_lockfile() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("packages/member")).unwrap();
    fs::create_dir_all(root.path().join("packages/sibling")).unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"workspaces":["packages/*"]}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("packages/member/package.json"),
        r#"{"dependencies":{"sibling":"file:../sibling"}}"#,
    )
    .unwrap();
    fs::write(root.path().join("packages/sibling/package.json"), "{}").unwrap();

    let outcome = discover_with_contexts(root.path(), &[], &[]);

    assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
    let dependency = outcome
        .discovery
        .dependencies
        .iter()
        .find(|dependency| dependency.name == "sibling")
        .expect("workspace dependency should be discovered");
    let declaration_directories = outcome
        .discovery
        .npm_contexts
        .get(&dependency.npm_declaration_key())
        .into_iter()
        .flatten()
        .filter_map(NpmLockContext::declaration_directory)
        .collect::<Vec<_>>();
    assert_eq!(
        declaration_directories,
        vec![root.path().join("packages/member").as_path()]
    );
}

#[test]
fn npm_workspace_member_dependencies_use_root_package_lock_context() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("packages/member")).unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"workspaces":["packages/*"]}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("packages/member/package.json"),
        r#"{"dependencies":{"member-only":"^1.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("package-lock.json"),
        r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "packages/member": {"dependencies":{"member-only":"^1.0.0"}},
                "node_modules/member-only": {
                    "version":"1.2.3",
                    "resolved":"https://registry.example.test/member-only-1.2.3.tgz",
                    "integrity":"sha512-member-only"
                }
            }
        }"#,
    )
    .unwrap();

    let outcome = discover_with_contexts(root.path(), &[], &[]);

    assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
    let dependency = outcome
        .discovery
        .dependencies
        .iter()
        .find(|dependency| dependency.name == "member-only")
        .expect("workspace dependency should be discovered");
    assert_eq!(dependency.resolved_version.as_deref(), Some("1.2.3"));
    assert_eq!(
        dependency.source_url.as_deref(),
        Some("https://registry.example.test/member-only-1.2.3.tgz")
    );
    assert_eq!(
        dependency.lockfile.as_deref(),
        Some(root.path().join("package-lock.json").as_path())
    );
    assert!(
        outcome
            .discovery
            .npm_contexts
            .contains_key(&dependency.id())
    );
}

#[test]
fn npm_workspace_member_dependencies_use_root_pnpm_importer() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("packages/member")).unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"workspaces":["packages/*"]}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("packages/member/package.json"),
        r#"{"dependencies":{"member-only":"^1.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("pnpm-lock.yaml"),
        r#"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      member-only:
        specifier: ^1.0.0
        version: 9.0.0
  packages/member:
    dependencies:
      member-only:
        specifier: ^1.0.0
        version: 1.2.3
packages:
  member-only@1.2.3:
    resolution:
      integrity: sha512-member-only
  member-only@9.0.0:
    resolution:
      integrity: sha512-wrong-importer
"#,
    )
    .unwrap();

    let outcome = discover_with_contexts(root.path(), &[], &[]);

    assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
    let dependency = outcome
        .discovery
        .dependencies
        .iter()
        .find(|dependency| dependency.name == "member-only")
        .expect("workspace dependency should be discovered");
    assert_eq!(dependency.resolved_version.as_deref(), Some("1.2.3"));
    assert_eq!(dependency.integrity.as_deref(), Some("sha512-member-only"));
    assert_eq!(
        dependency.lockfile.as_deref(),
        Some(root.path().join("pnpm-lock.yaml").as_path())
    );
}

#[test]
fn npm_workspace_member_dependencies_use_root_yarn_resolution() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("packages/member")).unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"workspaces":["packages/*"]}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("packages/member/package.json"),
        r#"{"dependencies":{"member-only":"^2.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("yarn.lock"),
        r#"
__metadata:
  version: 8

"member-only@npm:^2.0.0":
  version: 2.4.0
  resolution: "member-only@npm:2.4.0"
  integrity: sha512-member-only
"#,
    )
    .unwrap();

    let outcome = discover_with_contexts(root.path(), &[], &[]);

    assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
    let dependency = outcome
        .discovery
        .dependencies
        .iter()
        .find(|dependency| dependency.name == "member-only")
        .expect("workspace dependency should be discovered");
    assert_eq!(dependency.resolved_version.as_deref(), Some("2.4.0"));
    assert_eq!(dependency.integrity.as_deref(), Some("sha512-member-only"));
    assert_eq!(
        dependency.lockfile.as_deref(),
        Some(root.path().join("yarn.lock").as_path())
    );
}

#[test]
fn local_alternative_npm_lock_prevents_inherited_package_lock_fallback() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"dependencies":{"example":"^1"}}"#,
    )
    .unwrap();
    fs::write(root.path().join("yarn.lock"), "{}").unwrap();
    let inherited = NpmLockContext {
        lockfile: root.path().join("missing-package-lock.json"),
        package_path: String::new(),
    };

    let outcome = discover_with_contexts(root.path(), std::slice::from_ref(&inherited), &[]);
    assert!(outcome.errors.is_empty());
    assert_eq!(
        outcome.discovery.lockfiles,
        vec![root.path().join("yarn.lock")]
    );
}
