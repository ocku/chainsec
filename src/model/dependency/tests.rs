use std::{
    collections::{HashMap, HashSet, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    path::Path,
};

use super::{DenoLockfileSnapshot, Dependency, Ecosystem};

const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

fn dependency(url: &str) -> Dependency {
    let mut dependency = Dependency::declared(Ecosystem::Npm, "example", "example");
    dependency.resolved_version = Some(REVISION.to_owned());
    dependency.source_url = Some(url.to_owned());
    dependency
}

#[test]
fn classifies_npm_local_schemes_as_local() {
    for requirement in [
        "file:../package",
        "link:../package",
        "portal:../package",
        "workspace:*",
    ] {
        let dependency = Dependency::declared(Ecosystem::Npm, "example", requirement);
        assert!(dependency.is_local(), "accepted as remote: {requirement}");
    }

    let dependency = Dependency::declared(Ecosystem::Npm, "example", "^1.0.0");
    assert!(!dependency.is_local());
}

#[test]
fn local_source_ids_are_stable_and_location_distinct() {
    let dependency = Dependency::declared(Ecosystem::Npm, "shared", "file:./shared");

    let first = dependency.local_source_id(Path::new("/project/parent-a/shared"));
    let repeated = dependency.local_source_id(Path::new("/project/parent-a/shared"));
    let second = dependency.local_source_id(Path::new("/project/parent-b/shared"));

    assert_eq!(first, repeated);
    assert_ne!(first, second);
    assert!(first.starts_with("npm:shared@file:./shared#unverified@local-source:sha256:"));
}

#[test]
fn accepts_canonical_github_commit_archive() {
    let dependency = dependency(&format!(
        "https://codeload.github.com/owner/repository/tar.gz/{REVISION}"
    ));

    assert!(dependency.is_pinned_github());
    assert!(dependency.is_resolved());
    assert_eq!(
        dependency.github_archive_url().unwrap().as_str(),
        format!("https://codeload.github.com/owner/repository/tar.gz/{REVISION}")
    );
}

#[test]
fn unverified_pinned_github_archives_from_distinct_repositories_have_distinct_ids() {
    let first = dependency(&format!(
        "https://codeload.github.com/first-owner/example/tar.gz/{REVISION}"
    ));
    let second = dependency(&format!(
        "https://codeload.github.com/second-owner/example/tar.gz/{REVISION}"
    ));

    assert_ne!(first.id(), second.id());
}

#[test]
fn rejects_noncanonical_github_archive_urls() {
    let cases = [
        format!("https://codeload.github.com.attacker.example/owner/repository/tar.gz/{REVISION}"),
        format!("https://codeload.github.com@attacker.example/owner/repository/tar.gz/{REVISION}"),
        format!("http://codeload.github.com/owner/repository/tar.gz/{REVISION}"),
        format!("https://codeload.github.com:444/owner/repository/tar.gz/{REVISION}"),
        format!("https://user@codeload.github.com/owner/repository/tar.gz/{REVISION}"),
        format!("https://codeload.github.com/owner/repository/tar.gz/{REVISION}?download=1"),
        format!("https://codeload.github.com/owner/repository/tar.gz/{REVISION}#archive"),
        format!("https://codeload.github.com/owner/repository/zip/{REVISION}"),
        "https://codeload.github.com/owner/repository/tar.gz/short".to_owned(),
        format!("https://codeload.github.com/owner%2Frepository/tar.gz/{REVISION}"),
        format!("https://codeload.github.com/owner/repository/tar.gz/{REVISION}/extra"),
        "https://codeload.github.com/owner/repository/tar.gz/ffffffffffffffffffffffffffffffffffffffff"
            .to_owned(),
    ];

    for url in cases {
        let dependency = dependency(&url);
        assert!(!dependency.is_pinned_github(), "accepted {url}");
        assert!(!dependency.is_resolved(), "resolved {url}");
    }
}

#[test]
fn deno_lockfile_snapshot_retains_only_v5_redirect_topology() {
    let contents = r#"{
        "version":"5",
        "redirects":{
            "https://example.test:443/root.ts":"https://example.test:443/v1/root.ts"
        },
        "remote":{"https://example.test:443/v1/root.ts":"sha256-root"}
    }"#;
    let snapshot = DenoLockfileSnapshot::from_lockfile(
        contents.as_bytes(),
        &serde_json::from_str(contents).unwrap(),
    );

    assert_eq!(
        snapshot.redirects(),
        &HashMap::from([(
            "https://example.test/root.ts".to_owned(),
            "https://example.test/v1/root.ts".to_owned(),
        )])
    );

    let changed_redirect = contents.replacen(
        "https://example.test:443/v1/root.ts",
        "https://example.test:443/v2/root.ts",
        1,
    );
    let changed_snapshot = DenoLockfileSnapshot::from_lockfile(
        changed_redirect.as_bytes(),
        &serde_json::from_str(&changed_redirect).unwrap(),
    );
    assert_ne!(snapshot.identity(), changed_snapshot.identity());

    let v4_contents = contents.replacen("\"5\"", "\"4\"", 1);
    let v4_snapshot = DenoLockfileSnapshot::from_lockfile(
        v4_contents.as_bytes(),
        &serde_json::from_str(&v4_contents).unwrap(),
    );
    assert!(v4_snapshot.redirects().is_empty());
}

#[test]
fn deno_lockfile_snapshot_clone_and_hash_include_redirect_topology() {
    let remote_integrities = HashMap::from([(
        "https://example.test/root.ts".to_owned(),
        "sha256-root".to_owned(),
    )]);
    let first = DenoLockfileSnapshot::from_remote_integrities_and_redirects(
        "same-test-identity",
        remote_integrities.clone(),
        HashMap::from([(
            "https://example.test/root.ts".to_owned(),
            "https://example.test/v1/root.ts".to_owned(),
        )]),
    );
    let second = DenoLockfileSnapshot::from_remote_integrities_and_redirects(
        "same-test-identity",
        remote_integrities,
        HashMap::from([(
            "https://example.test/root.ts".to_owned(),
            "https://example.test/v2/root.ts".to_owned(),
        )]),
    );
    let cloned = first.clone();

    assert!(first.shares_remote_integrities_with(&cloned));
    assert!(first.shares_redirects_with(&cloned));
    assert_ne!(first, second);

    let hash = |snapshot: &DenoLockfileSnapshot| {
        let mut hasher = DefaultHasher::new();
        snapshot.hash(&mut hasher);
        hasher.finish()
    };
    assert_eq!(hash(&first), hash(&cloned));
    assert_ne!(hash(&first), hash(&second));
    assert_eq!(HashSet::from([first, cloned, second]).len(), 2);
}
