use std::fs;

use super::super::{discover_with_contexts, discover_with_contexts_and_limits};
use crate::{error::Error, model::EngineLimits};

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
