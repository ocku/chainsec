use std::{collections::HashMap, fs};

use super::*;
use crate::manifests::shared::{ManifestRoot, with_manifest_roots};

#[test]
fn includes_development_dependencies_with_npm_precedence() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("package.json");
    fs::write(
        &path,
        r#"{
            "devDependencies":{"both":"development","dev":"development","dev-peer":"development"},
            "dependencies":{"both":"direct","direct-peer":"direct"},
            "optionalDependencies":{"both":"optional","optional-peer":"optional"},
            "peerDependencies":{
                "both":"peer","direct-peer":"peer","optional-peer":"peer","dev-peer":"peer","peer":"peer"
            }
        }"#,
    )
    .unwrap();

    let (dependencies, _) = parse(&path).unwrap();
    let requirements: HashMap<_, _> = dependencies
        .into_iter()
        .map(|dependency| (dependency.name, dependency.requirement))
        .collect();

    assert_eq!(requirements["both"], "optional");
    assert_eq!(requirements["direct-peer"], "direct");
    assert_eq!(requirements["optional-peer"], "optional");
    assert_eq!(requirements["dev"], "development");
    assert_eq!(requirements["dev-peer"], "development");
    assert_eq!(requirements["peer"], "peer");
}

#[test]
fn enrichment_reports_selection_even_when_a_local_lock_has_no_matches() {
    let temporary = tempfile::tempdir().unwrap();
    fs::write(
        temporary.path().join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{}}}"#,
    )
    .unwrap();
    let mut dependencies = [Dependency::declared(Ecosystem::Npm, "missing", "1")];
    let mut lockfiles = Vec::new();

    let root = ManifestRoot::open(temporary.path()).unwrap();
    let result = enrich(&root, &mut dependencies, &mut lockfiles).unwrap();

    assert!(result.local_lockfile_selected);
    assert!(result.contexts.is_empty());
}

#[cfg(unix)]
#[test]
fn local_lock_selection_uses_the_opened_root_after_path_replacement() {
    let parent = tempfile::tempdir().unwrap();
    let root_path = parent.path().join("root");
    fs::create_dir(&root_path).unwrap();
    fs::write(
        root_path.join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{}}}"#,
    )
    .unwrap();
    let root = ManifestRoot::open(&root_path).unwrap();

    fs::rename(&root_path, parent.path().join("original")).unwrap();
    fs::create_dir(&root_path).unwrap();
    fs::write(root_path.join("package-lock.json"), "{").unwrap();

    let mut dependencies = [Dependency::declared(Ecosystem::Npm, "missing", "1")];
    let mut lockfiles = Vec::new();
    let result = with_manifest_roots(std::slice::from_ref(&root), || {
        enrich(&root, &mut dependencies, &mut lockfiles)
    })
    .unwrap()
    .unwrap();

    assert!(result.local_lockfile_selected);
}
