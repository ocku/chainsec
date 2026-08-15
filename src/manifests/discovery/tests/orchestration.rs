use std::{fs, path::PathBuf};

use super::super::orchestration::normalize_discovery;
use super::super::{discover, discover_with_contexts, discover_with_contexts_and_limits};
use crate::{
    error::Error,
    model::{Dependency, Ecosystem, EngineLimits},
};

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
