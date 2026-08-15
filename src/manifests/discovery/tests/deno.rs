use std::fs;

use super::super::discover_with_contexts;
use crate::manifests::{NpmLockContext, strip_jsonc};

#[test]
fn jsonc_preserves_comment_markers_in_strings() {
    let clean = strip_jsonc("{\"url\":\"https://example.test/a//b\" // comment\n}").unwrap();
    let value: serde_json::Value = serde_json::from_str(&clean).unwrap();
    assert_eq!(value["url"], "https://example.test/a//b");
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

#[test]
fn deno_workspace_local_dependency_retains_its_package_json_directory() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("deno.json"),
        r#"{"workspace":["packages/*"]}"#,
    )
    .unwrap();
    fs::create_dir_all(root.path().join("packages/member")).unwrap();
    fs::write(
        root.path().join("packages/member/package.json"),
        r#"{"dependencies":{"sibling":"file:../sibling"}}"#,
    )
    .unwrap();

    let outcome = discover_with_contexts(root.path(), &[], &[]);

    assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
    let dependency = outcome
        .discovery
        .dependencies
        .iter()
        .find(|dependency| dependency.name == "sibling")
        .expect("Deno workspace local dependency should be discovered");
    assert_eq!(dependency.ecosystem, crate::model::Ecosystem::Deno);
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
