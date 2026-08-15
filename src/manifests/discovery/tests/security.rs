use std::fs;

use super::super::discover_with_contexts;

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
