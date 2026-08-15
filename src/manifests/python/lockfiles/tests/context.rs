use super::*;

#[test]
fn inherited_contexts_independently_union_distinct_authorized_resolutions() {
    let first_hash = "1".repeat(64);
    let second_hash = "2".repeat(64);
    let (_first_directory, first_path) = write_lock(
        "poetry.lock",
        &format!(
            r#"[[package]]
name = "demo"
version = "1.0"
files = [{{url = "https://example.test/demo-1.0.whl", hash = "sha256:{first_hash}"}}]
"#,
        ),
    );
    let (_second_directory, second_path) = write_lock(
        "poetry.lock",
        &format!(
            r#"[[package]]
name = "demo"
version = "2.0"
files = [{{url = "https://example.test/demo-2.0.tar.gz", hash = "sha256:{second_hash}"}}]
"#,
        ),
    );
    let project = tempdir().unwrap();
    let root = ManifestRoot::open(project.path()).unwrap();
    let inherited = [
        PythonLockContext::Poetry(first_path.clone()),
        PythonLockContext::Poetry(second_path.clone()),
    ];
    let mut dependencies = vec![dependency("demo>=1")];
    let mut lockfiles = Vec::new();

    let contexts = enrich(&root, &mut dependencies, &mut lockfiles, &inherited, 2).unwrap();

    assert_eq!(contexts.len(), 2);
    assert_eq!(lockfiles, [first_path.clone(), second_path.clone()]);
    assert_eq!(dependencies.len(), 2);

    let first = dependencies
        .iter()
        .find(|dependency| dependency.resolved_version.as_deref() == Some("1.0"))
        .unwrap();
    assert_eq!(
        first.source_url.as_deref(),
        Some("https://example.test/demo-1.0.whl")
    );
    assert_eq!(
        first.integrity.as_deref(),
        Some(format!("sha256:{first_hash}").as_str())
    );
    assert_eq!(first.lockfile.as_deref(), Some(first_path.as_path()));

    let second = dependencies
        .iter()
        .find(|dependency| dependency.resolved_version.as_deref() == Some("2.0"))
        .unwrap();
    assert_eq!(
        second.source_url.as_deref(),
        Some("https://example.test/demo-2.0.tar.gz")
    );
    assert_eq!(
        second.integrity.as_deref(),
        Some(format!("sha256:{second_hash}").as_str())
    );
    assert_eq!(second.lockfile.as_deref(), Some(second_path.as_path()));
}

#[test]
fn inherited_contexts_drop_unresolved_fallbacks_only_for_resolved_declarations() {
    let first_hash = "a".repeat(64);
    let second_hash = "b".repeat(64);
    let (_first_directory, first_path) = write_lock(
        "poetry.lock",
        &format!(
            r#"[[package]]
name = "child-a"
version = "1.0"
files = [{{url = "https://example.test/child-a.whl", hash = "sha256:{first_hash}"}}]
"#,
        ),
    );
    let (_second_directory, second_path) = write_lock(
        "poetry.lock",
        &format!(
            r#"[[package]]
name = "child-b"
version = "2.0"
files = [{{url = "https://example.test/child-b.whl", hash = "sha256:{second_hash}"}}]
"#,
        ),
    );
    let project = tempdir().unwrap();
    let root = ManifestRoot::open(project.path()).unwrap();
    let inherited = [
        PythonLockContext::Poetry(first_path.clone()),
        PythonLockContext::Poetry(second_path.clone()),
    ];
    let mut dependencies = vec![
        dependency("child-a"),
        dependency("child-b"),
        dependency("missing"),
    ];
    let mut lockfiles = Vec::new();

    enrich(&root, &mut dependencies, &mut lockfiles, &inherited, 3).unwrap();

    assert_eq!(dependencies.len(), 3);
    let child_a = dependencies
        .iter()
        .find(|dependency| dependency.name == "child-a")
        .unwrap();
    assert_eq!(child_a.resolved_version.as_deref(), Some("1.0"));
    assert_eq!(child_a.lockfile.as_deref(), Some(first_path.as_path()));

    let child_b = dependencies
        .iter()
        .find(|dependency| dependency.name == "child-b")
        .unwrap();
    assert_eq!(child_b.resolved_version.as_deref(), Some("2.0"));
    assert_eq!(child_b.lockfile.as_deref(), Some(second_path.as_path()));

    let missing = dependencies
        .iter()
        .find(|dependency| dependency.name == "missing")
        .unwrap();
    assert_eq!(missing, &dependency("missing"));
}

#[cfg(unix)]
#[test]
fn lock_selection_uses_the_opened_root_after_path_replacement() {
    let parent = tempdir().unwrap();
    let root_path = parent.path().join("root");
    fs::create_dir(&root_path).unwrap();
    fs::write(
        root_path.join("poetry.lock"),
        "[metadata]\nlock-version = \"2.0\"\n[[package]]\nname = \"trusted\"\nversion = \"1\"\n",
    )
    .unwrap();
    let root = ManifestRoot::open(&root_path).unwrap();

    fs::rename(&root_path, parent.path().join("original")).unwrap();
    fs::create_dir(&root_path).unwrap();
    fs::write(root_path.join("poetry.lock"), "package = {}").unwrap();

    let mut dependencies = Vec::new();
    let mut lockfiles = Vec::new();
    let contexts = with_manifest_roots(std::slice::from_ref(&root), || {
        enrich(
            &root,
            &mut dependencies,
            &mut lockfiles,
            &[],
            crate::model::EngineLimits::default().max_packages,
        )
    })
    .unwrap()
    .unwrap();

    assert_eq!(contexts.len(), 1);
    assert_eq!(lockfiles, vec![root_path.join("poetry.lock")]);
}
