use std::{fs, path::PathBuf};

use super::*;
use crate::{
    manifests::strip_jsonc,
    model::{Ecosystem, EngineLimits},
};

#[test]
fn jsonc_preserves_comment_markers_in_strings() {
    let clean = strip_jsonc("{\"url\":\"https://example.test/a//b\" // comment\n}").unwrap();
    let value: serde_json::Value = serde_json::from_str(&clean).unwrap();
    assert_eq!(value["url"], "https://example.test/a//b");
}

#[test]
fn partial_discovery_retains_successful_ecosystems_but_public_api_errors() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("package.json"), "{").unwrap();
    fs::write(
        root.path().join("deno.json"),
        r#"{"imports":{"example":"https://example.test/mod.ts"}}"#,
    )
    .unwrap();

    let outcome = discover_with_contexts(root.path(), &[], &[]);
    assert_eq!(outcome.errors.len(), 1);
    assert_eq!(outcome.discovery.dependencies.len(), 1);
    assert_eq!(outcome.discovery.dependencies[0].ecosystem, Ecosystem::Deno);
    assert!(discover(root.path()).is_err());
}

#[test]
fn configured_package_limit_applies_to_all_manifest_ecosystems() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"dependencies":{"npm-package":"1"}}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("pyproject.toml"),
        "[project]\ndependencies = [\"python-package==1\"]\n",
    )
    .unwrap();
    fs::write(
        root.path().join("deno.json"),
        r#"{"imports":{"deno-package":"npm:deno-package@1"}}"#,
    )
    .unwrap();

    let limits = EngineLimits {
        max_packages: 2,
        ..EngineLimits::default()
    };
    let outcome = discover_with_contexts_and_limits(root.path(), &[], &[], &limits);

    assert_eq!(outcome.discovery.dependencies.len(), limits.max_packages);
    assert!(
        outcome
            .errors
            .iter()
            .any(|error| matches!(error, Error::LimitExceeded { .. }))
    );
}

#[test]
fn exact_dedup_preserves_conflicting_provenance_and_deduplicates_lockfiles() {
    let mut first = Dependency::declared(Ecosystem::Npm, "example", "^1");
    first.lockfile = Some(PathBuf::from("a.lock"));
    let mut second = first.clone();
    second.lockfile = Some(PathBuf::from("b.lock"));
    let mut dependencies = vec![second.clone(), first.clone(), first.clone()];
    let mut lockfiles = vec![
        PathBuf::from("b.lock"),
        PathBuf::from("a.lock"),
        PathBuf::from("b.lock"),
    ];

    normalize_discovery(&mut dependencies, &mut lockfiles);

    assert_eq!(dependencies, vec![first, second]);
    assert_eq!(
        lockfiles,
        vec![PathBuf::from("a.lock"), PathBuf::from("b.lock")]
    );
}

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
fn malformed_python_lockfile_keeps_declared_dependencies_visible() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("pyproject.toml"),
        "[project]\ndependencies = [\"example>=1\"]\n",
    )
    .unwrap();
    fs::write(
        root.path().join("poetry.lock"),
        "[[package]]\nname = \"example\"\nversion = \"not-a-version\"\n",
    )
    .unwrap();

    let outcome = discover_with_contexts(root.path(), &[], &[]);

    assert_eq!(outcome.errors.len(), 1);
    assert_eq!(outcome.discovery.dependencies.len(), 1);
    assert_eq!(outcome.discovery.dependencies[0].name, "example");
    assert!(outcome.discovery.dependencies[0].lockfile.is_none());
}

#[test]
fn python_artifact_expansion_respects_the_configured_package_limit() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("Pipfile"),
        "[packages]\nexample = \"==1\"\n",
    )
    .unwrap();
    fs::write(
        root.path().join("Pipfile.lock"),
        format!(
            r#"{{"_meta":{{"pipfile-spec":6}},"default":{{"example":{{"version":"==1","hashes":["sha256:{}","sha256:{}"]}}}},"develop":{{}}}}"#,
            "1".repeat(64),
            "2".repeat(64)
        ),
    )
    .unwrap();
    let limits = EngineLimits {
        max_packages: 1,
        ..EngineLimits::default()
    };

    let outcome = discover_with_contexts_and_limits(root.path(), &[], &[], &limits);

    assert!(
        outcome
            .errors
            .iter()
            .any(|error| matches!(error, Error::LimitExceeded { .. }))
    );
    assert_eq!(outcome.discovery.dependencies.len(), 1);
    assert_eq!(outcome.discovery.dependencies[0].name, "example");
    assert!(outcome.discovery.dependencies[0].lockfile.is_none());
}

#[test]
fn deno_discovery_rejects_ambiguous_config_names() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("deno.json"), "{}").unwrap();
    fs::write(root.path().join("deno.jsonc"), "{}").unwrap();

    let outcome = discover_with_contexts(root.path(), &[], &[]);

    assert_eq!(outcome.errors.len(), 1);
    assert!(
        outcome.errors[0]
            .to_string()
            .contains("both deno.json and deno.jsonc")
    );
}

#[test]
fn deno_discovery_uses_custom_lock_and_ignores_stale_default_lock() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("locks")).unwrap();
    fs::write(
        root.path().join("deno.json"),
        r#"{"lock":"locks/custom.lock","imports":{"demo":"npm:demo@^1"}}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("locks/custom.lock"),
        r#"{"version":"4","specifiers":{"npm:demo@^1":"1.2.3"},"npm":{"demo@1.2.3":{"integrity":"sha512-custom"}}}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("deno.lock"),
        r#"{"version":"4","specifiers":{"npm:demo@^1":"9.9.9"},"npm":{"demo@9.9.9":{"integrity":"sha512-stale"}}}"#,
    )
    .unwrap();

    let outcome = discover_with_contexts(root.path(), &[], &[]);

    assert!(outcome.errors.is_empty());
    assert_eq!(outcome.discovery.dependencies.len(), 1);
    assert_eq!(
        outcome.discovery.dependencies[0]
            .resolved_version
            .as_deref(),
        Some("1.2.3")
    );
    assert_eq!(
        outcome.discovery.lockfiles,
        vec![root.path().join("locks/custom.lock")]
    );
}

#[test]
fn deno_discovery_does_not_use_default_lock_when_disabled() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("deno.json"),
        r#"{"lock":false,"imports":{"demo":"npm:demo@^1"}}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("deno.lock"),
        r#"{"version":"4","specifiers":{"npm:demo@^1":"9.9.9"},"npm":{"demo@9.9.9":{"integrity":"sha512-stale"}}}"#,
    )
    .unwrap();

    let outcome = discover_with_contexts(root.path(), &[], &[]);

    assert!(outcome.errors.is_empty());
    assert!(outcome.discovery.dependencies[0].resolved_version.is_none());
    assert!(outcome.discovery.dependencies[0].lockfile.is_none());
    assert!(outcome.discovery.lockfiles.is_empty());
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
fn deno_workspace_dependencies_are_discovered_and_local_aliases_filtered() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("deno.json"),
        r#"{"workspace":["members/*"],"imports":{"root":"npm:root@1","local":"./mod.ts"}}"#,
    )
    .unwrap();
    fs::create_dir_all(root.path().join("members/a")).unwrap();
    fs::write(
        root.path().join("members/a/deno.json"),
        r#"{"imports":{"member":"jsr:@scope/member@1"}}"#,
    )
    .unwrap();

    let outcome = discover_with_contexts(root.path(), &[], &[]);

    assert!(outcome.errors.is_empty());
    let names = outcome
        .discovery
        .dependencies
        .iter()
        .map(|dependency| dependency.name.as_str())
        .collect::<std::collections::HashSet<_>>();
    assert!(names.contains("root"));
    assert!(names.contains("member"));
    assert!(!names.contains("local"));
}

#[cfg(unix)]
#[test]
fn npm_discovery_rejects_symlinked_manifest() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    fs::write(outside.path(), r#"{"dependencies":{"outside":"1"}}"#).unwrap();
    symlink(outside.path(), root.path().join("package.json")).unwrap();

    let outcome = discover_with_contexts(root.path(), &[], &[]);

    assert_eq!(outcome.errors.len(), 1);
    assert!(outcome.discovery.dependencies.is_empty());
    assert!(matches!(outcome.errors[0], crate::error::Error::Io { .. }));
}

#[cfg(unix)]
#[test]
fn python_discovery_rejects_symlinked_lockfile_during_selection() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    fs::write(
        root.path().join("pyproject.toml"),
        "[project]\ndependencies = [\"example>=1\"]\n",
    )
    .unwrap();
    fs::write(outside.path(), "").unwrap();
    symlink(outside.path(), root.path().join("poetry.lock")).unwrap();

    let outcome = discover_with_contexts(root.path(), &[], &[]);

    assert_eq!(outcome.errors.len(), 1);
    assert!(outcome.discovery.dependencies.is_empty());
    assert!(matches!(outcome.errors[0], crate::error::Error::Io { .. }));
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
