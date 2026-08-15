use super::*;

fn publication_fixture(
    limits: crate::model::EngineLimits,
    ecosystem: Ecosystem,
    requirement: &str,
) -> (
    tempfile::TempDir,
    SourceFetcher,
    Dependency,
    Acquisition,
    PathBuf,
) {
    let root = tempfile::tempdir().unwrap();
    let fetcher = SourceFetcher::new(
        root.path().join("cache"),
        super::super::super::FetchPolicy::default(),
        limits,
    )
    .unwrap();
    let mut dependency = Dependency::declared(ecosystem, "fixture", requirement);
    dependency.resolved_version = Some("1.0.0".to_owned());
    dependency.integrity = Some("sha256:fixture".to_owned());
    let acquisition = acquisition(&fetcher, &dependency);
    let workspace = root.path().join("workspace");
    fs::create_dir_all(workspace.join("source")).unwrap();
    (root, fetcher, dependency, acquisition, workspace)
}

fn publish_fixture(
    fetcher: &SourceFetcher,
    dependency: &Dependency,
    acquisition: &Acquisition,
    workspace: &Path,
) -> Result<FetchMetadata> {
    fetcher.publish(
        dependency,
        acquisition,
        &Url::parse("https://example.test/fixture").unwrap(),
        "sha256:fixture".to_owned(),
        workspace,
        &workspace.join("source"),
    )
}

#[test]
fn oversized_artifact_is_rejected_during_cache_publication() {
    let limits = crate::model::EngineLimits {
        max_archive_size: 3,
        ..crate::model::EngineLimits::default()
    };
    let (_root, fetcher, dependency, acquisition, workspace) =
        publication_fixture(limits, Ecosystem::Npm, "1.0.0");
    fs::write(workspace.join(CACHED_ARTIFACT), b"four").unwrap();

    assert!(matches!(
        publish_fixture(&fetcher, &dependency, &acquisition, &workspace),
        Err(Error::LimitExceeded { resource, limit: 3 }) if resource == "archive bytes"
    ));
    assert!(!acquisition.destination.exists());
}

#[test]
fn cache_publication_stops_waiting_at_deadline_and_does_not_publish() {
    let (_root, fetcher, dependency, acquisition, workspace) = publication_fixture(
        crate::model::EngineLimits::default(),
        Ecosystem::Npm,
        "1.0.0",
    );
    fs::write(workspace.join(CACHED_ARTIFACT), b"artifact").unwrap();
    let _held_lock = lock_entry(&acquisition).unwrap();
    let budget = crate::fetcher::budget::AcquisitionBudget::new(
        std::time::Duration::from_millis(25),
        u64::MAX,
    );
    let deadline = budget.deadline_guard();
    let started = std::time::Instant::now();

    let source_url = Url::parse("https://example.test/fixture").unwrap();
    let source = workspace.join("source");
    let error = fetcher
        .publish_with_effective_source_url(CachePublication {
            dependency: &dependency,
            acquisition: &acquisition,
            source_url: &source_url,
            effective_source_url: None,
            digest: "sha256:fixture".to_owned(),
            temporary: &workspace,
            source_directory: &source,
            deadline: &deadline,
        })
        .unwrap_err();

    assert_eq!(error.code(), "limit_exceeded", "{error}");
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    assert!(!acquisition.destination.exists());
}

#[test]
fn retained_source_publication_enforces_aggregate_extracted_size() {
    let limits = crate::model::EngineLimits {
        max_source_file_size: 3,
        max_extracted_size: 5,
        ..crate::model::EngineLimits::default()
    };
    let (_root, fetcher, dependency, acquisition, workspace) =
        publication_fixture(limits, Ecosystem::Deno, "jsr:@scope/fixture@1.0.0");
    fs::write(workspace.join(CACHED_ARTIFACT), b"manifest").unwrap();
    fs::write(workspace.join("source/first.ts"), b"abc").unwrap();
    fs::write(workspace.join("source/second.ts"), b"def").unwrap();

    assert!(matches!(
        publish_fixture(&fetcher, &dependency, &acquisition, &workspace),
        Err(Error::LimitExceeded { resource, .. }) if resource == "extracted bytes"
    ));
    assert!(!acquisition.destination.exists());
}

#[test]
fn retained_source_publication_does_not_apply_scan_file_limit_or_count_directories() {
    let limits = crate::model::EngineLimits {
        max_source_file_size: 3,
        max_extracted_size: 10,
        max_extracted_files: 1,
        ..crate::model::EngineLimits::default()
    };
    let (_root, fetcher, dependency, acquisition, workspace) =
        publication_fixture(limits, Ecosystem::Deno, "jsr:@scope/fixture@1.0.0");
    fs::write(workspace.join(CACHED_ARTIFACT), b"manifest").unwrap();
    fs::create_dir_all(workspace.join("source/nested/deep")).unwrap();
    fs::write(workspace.join("source/nested/deep/module.ts"), b"four").unwrap();

    assert!(publish_fixture(&fetcher, &dependency, &acquisition, &workspace).is_ok());
}

#[cfg(unix)]
#[test]
fn unsafe_retained_source_entries_are_rejected_during_publication() {
    use std::{ffi::CString, os::unix::ffi::OsStrExt, os::unix::fs::symlink};

    for kind in ["symlink", "fifo"] {
        let (_root, fetcher, dependency, acquisition, workspace) = publication_fixture(
            crate::model::EngineLimits::default(),
            Ecosystem::Deno,
            "jsr:@scope/fixture@1.0.0",
        );
        fs::write(workspace.join(CACHED_ARTIFACT), b"manifest").unwrap();
        let unsafe_entry = workspace.join("source/unsafe.ts");
        if kind == "symlink" {
            symlink(workspace.join(CACHED_ARTIFACT), &unsafe_entry).unwrap();
        } else {
            let path = CString::new(unsafe_entry.as_os_str().as_bytes()).unwrap();
            // SAFETY: `path` is NUL-terminated and names a test-owned path.
            assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        }

        assert!(matches!(
            publish_fixture(&fetcher, &dependency, &acquisition, &workspace),
            Err(Error::Policy { operation, .. }) if operation == "cache publication"
        ));
        assert!(!acquisition.destination.exists());
    }
}

#[test]
fn archive_cache_retains_only_the_verified_artifact() {
    let (_cache, fetcher, dependency) = cached_fixture();
    let destination = destination(&fetcher, &dependency);

    assert!(destination.join(CACHED_ARTIFACT).is_file());
    assert!(destination.join(COMPLETION_MARKER).is_file());
    assert!(!destination.join("source").exists());
}
fn publish_fixture_again(
    root: &Path,
    fetcher: &SourceFetcher,
    dependency: &Dependency,
    name: &str,
) -> FetchMetadata {
    let archive = fixture_archive();
    let temporary = root.join(name);
    let source = temporary.join("source/package");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("index.js"), b"module.exports = 1;\n").unwrap();
    write_cached_artifact(&temporary, &archive).unwrap();
    fetcher
        .publish(
            dependency,
            &acquisition(fetcher, dependency),
            &Url::parse("https://example.test/fixture.tgz").unwrap(),
            format!("sha256:{}", hex::encode(Sha256::digest(&archive))),
            &temporary,
            &source,
        )
        .unwrap()
}

#[test]
fn cache_publication_keeps_an_existing_valid_winner() {
    let (cache, fetcher, dependency) = cached_fixture();
    let destination = destination(&fetcher, &dependency);
    fs::write(destination.join("winner-only"), "winner").unwrap();

    let fetched =
        publish_fixture_again(cache.path(), &fetcher, &dependency, "competing-publication");

    assert_eq!(
        fs::read_to_string(destination.join("winner-only")).unwrap(),
        "winner"
    );
    assert_eq!(
        fs::read_to_string(fetched.source.join("index.js")).unwrap(),
        "module.exports = 1;\n"
    );
}

#[test]
fn cache_publication_replaces_an_invalid_entry_under_the_entry_lock() {
    let (cache, fetcher, dependency) = cached_fixture();
    let destination = destination(&fetcher, &dependency);
    fs::write(destination.join(CACHED_ARTIFACT), b"corrupt archive").unwrap();
    assert!(cached(&fetcher, &dependency).is_none());

    publish_fixture_again(cache.path(), &fetcher, &dependency, "replacement");

    let restored = cached(&fetcher, &dependency).unwrap();
    assert_eq!(
        fs::read_to_string(restored.source.join("index.js")).unwrap(),
        "module.exports = 1;\n"
    );
}

#[test]
fn npm_sha512_integrity_allows_cache_hits_after_verified_publication() {
    let (_cache, fetcher, dependency) = cached_fixture_with_integrity(IntegrityAlgorithm::Sha512);

    assert!(cached(&fetcher, &dependency).is_some());
}
