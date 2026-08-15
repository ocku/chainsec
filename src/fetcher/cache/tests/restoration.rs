use super::*;

#[test]
fn cache_hits_use_independent_workspaces_without_republishing() {
    let (_cache, fetcher, dependency) = cached_fixture();
    let retained = destination(&fetcher, &dependency);

    let first = cached(&fetcher, &dependency).unwrap();
    let second = cached(&fetcher, &dependency).unwrap();
    let first_source = first.source.clone();
    let second_source = second.source.clone();

    assert_ne!(first_source, second_source);
    assert!(!first_source.starts_with(&retained));
    assert!(!second_source.starts_with(&retained));
    assert!(
        !first_source
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join(CACHED_ARTIFACT)
            .exists()
    );
    assert!(
        !second_source
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join(CACHED_ARTIFACT)
            .exists()
    );
    assert_eq!(
        fs::read(first_source.join("index.js")).unwrap(),
        b"module.exports = 1;\n"
    );
    drop(second);
    drop(first);
    assert!(first_source.is_dir());
    assert!(second_source.is_dir());
    assert!(retained.is_dir());

    drop(fetcher);
    assert!(!first_source.exists());
    assert!(!second_source.exists());
    assert!(retained.is_dir());
}

#[tokio::test]
async fn remote_root_cache_hits_honor_the_acquisition_deadline() {
    let (_cache, mut fetcher, dependency) = cached_fixture();
    fetcher.limits.max_acquisition_duration = std::time::Duration::ZERO;

    let error = fetcher.fetch_remote_root(dependency).await.unwrap_err();

    assert_eq!(error.code(), "limit_exceeded");
    assert!(error.to_string().contains("package acquisition seconds"));
}

#[test]
fn expired_deadline_stops_cache_restoration_without_mutating_the_entry() {
    let (_cache, fetcher, dependency) = cached_fixture();
    let acquisition = acquisition(&fetcher, &dependency);
    let retained = acquisition.destination.clone();
    let deadline =
        crate::fetcher::budget::AcquisitionBudget::new(std::time::Duration::ZERO, u64::MAX)
            .deadline_guard();

    let error = match fetcher.cached_before(&dependency, &acquisition, &deadline) {
        Err(error) => error,
        Ok(_) => panic!("expired cache restoration unexpectedly completed"),
    };

    assert_eq!(error.code(), "limit_exceeded", "{error}");
    assert!(retained.is_dir());
    assert!(retained.join(COMPLETION_MARKER).is_file());
}

#[test]
fn tampered_cached_archive_is_rejected_and_removed() {
    let (_cache, fetcher, dependency) = cached_fixture();
    let destination = destination(&fetcher, &dependency);
    fs::write(destination.join(CACHED_ARTIFACT), b"attacker archive").unwrap();

    assert!(cached(&fetcher, &dependency).is_none());
    assert!(!destination.exists());
}

#[test]
fn cache_mutation_after_restoration_cannot_change_scanner_source() {
    let (_cache, fetcher, dependency) = cached_fixture();
    let restored = cached(&fetcher, &dependency).unwrap();

    fs::write(
        destination(&fetcher, &dependency).join(CACHED_ARTIFACT),
        b"attacker archive",
    )
    .unwrap();

    assert_eq!(
        fs::read(restored.source.join("index.js")).unwrap(),
        b"module.exports = 1;\n"
    );
}

#[cfg(unix)]
#[test]
fn cache_restoration_workspace_is_owner_only() {
    use std::os::unix::fs::MetadataExt;

    let (_cache, fetcher, dependency) = cached_fixture();
    let restored = cached(&fetcher, &dependency).unwrap();
    let workspace = restored.source.parent().unwrap().parent().unwrap();

    assert_eq!(fs::metadata(workspace).unwrap().mode() & 0o777, 0o700);
    assert_eq!(
        fs::metadata(restored.source.parent().unwrap())
            .unwrap()
            .mode()
            & 0o777,
        0o700
    );
}

#[test]
fn github_completion_retains_workspace_without_publishing_a_cache_entry() {
    let cache = tempfile::tempdir().unwrap();
    let fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        super::super::super::FetchPolicy::default(),
        crate::model::EngineLimits::default(),
    )
    .unwrap();
    let archive = fixture_archive();
    let revision = "0123456789012345678901234567890123456789";
    let source_url = Url::parse(&format!(
        "https://codeload.github.com/owner/repository/tar.gz/{revision}"
    ))
    .unwrap();
    let mut dependency = Dependency::declared(
        Ecosystem::Npm,
        "owner/repository",
        format!("owner/repository@{revision}"),
    );
    dependency.resolved_version = Some(revision.to_owned());
    dependency.source_url = Some(source_url.to_string());

    let temporary = cache.path().join("temporary");
    let source = temporary.join("source/package");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("index.js"), b"module.exports = 1;\n").unwrap();
    let acquisition = acquisition(&fetcher, &dependency);
    let fetched = fetcher
        .complete_without_cache(
            &dependency,
            &source_url,
            format!("sha256:{}", hex::encode(Sha256::digest(&archive))),
            &temporary,
            &source,
        )
        .unwrap();

    assert_eq!(fetched.source, source);
    assert!(!fetched.cache_hit);
    assert!(temporary.is_dir());
    assert!(!acquisition.destination.exists());
    assert!(matches!(
        fetcher.cached(&dependency, &acquisition).unwrap(),
        CacheLookup::Miss
    ));
}

#[test]
fn deno_npm_cache_restoration_does_not_trust_marker_url_for_source_type() {
    let cache = tempfile::tempdir().unwrap();
    let fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        super::super::super::FetchPolicy::default(),
        crate::model::EngineLimits::default(),
    )
    .unwrap();
    let archive = fixture_archive();
    let mut dependency = Dependency::declared(Ecosystem::Deno, "fixture", "npm:fixture@1.0.0");
    dependency.resolved_version = Some("1.0.0".to_owned());
    dependency.integrity = Some(integrity(IntegrityAlgorithm::Sha256, &archive));

    let temporary = cache.path().join("temporary");
    let source = temporary.join("source/package");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("index.js"), b"module.exports = 1;\n").unwrap();
    write_cached_artifact(&temporary, &archive).unwrap();
    let acquisition = acquisition(&fetcher, &dependency);
    fetcher
        .publish(
            &dependency,
            &acquisition,
            &Url::parse("https://registry.example.test/fixture.tgz").unwrap(),
            format!("sha256:{}", hex::encode(Sha256::digest(&archive))),
            &temporary,
            &source,
        )
        .unwrap();

    let marker = acquisition.destination.join(COMPLETION_MARKER);
    let mut metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(&marker).unwrap()).unwrap();
    metadata["source_url"] =
        serde_json::Value::String("https://attacker.test/fixture.ts".to_owned());
    fs::write(marker, serde_json::to_vec(&metadata).unwrap()).unwrap();

    let CacheLookup::Hit(restored) = fetcher.cached(&dependency, &acquisition).unwrap() else {
        panic!("expected a cache hit");
    };
    assert_eq!(
        fs::read(restored.source.join("index.js")).unwrap(),
        b"module.exports = 1;\n"
    );
    assert_eq!(restored.source_url, UNVERIFIED_CACHE_SOURCE_URL);
}
#[test]
fn tampered_source_url_metadata_is_rejected() {
    let (_cache, fetcher, dependency) = cached_fixture();
    let marker = destination(&fetcher, &dependency).join(COMPLETION_MARKER);
    let mut metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(&marker).unwrap()).unwrap();
    metadata["source_url"] =
        serde_json::Value::String("https://attacker.test/fixture.tgz".to_owned());
    fs::write(marker, serde_json::to_vec(&metadata).unwrap()).unwrap();

    assert!(cached(&fetcher, &dependency).is_none());
}

#[test]
fn non_http_source_url_metadata_is_rejected() {
    let (_cache, fetcher, dependency) = cached_fixture();
    let marker = destination(&fetcher, &dependency).join(COMPLETION_MARKER);
    let mut metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(&marker).unwrap()).unwrap();
    metadata["source_url"] = serde_json::Value::String("file:///tmp/fixture.tgz".to_owned());
    fs::write(marker, serde_json::to_vec(&metadata).unwrap()).unwrap();

    assert!(cached(&fetcher, &dependency).is_none());
}

#[test]
fn legacy_completion_fields_are_ignored() {
    let (_cache, fetcher, dependency) = cached_fixture();
    let marker = destination(&fetcher, &dependency).join(COMPLETION_MARKER);
    let mut metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(&marker).unwrap()).unwrap();
    metadata["source_directory"] = serde_json::Value::String("source/package".to_owned());
    metadata["extracted_files"] = serde_json::Value::from(1_u64);
    metadata["extracted_bytes"] = serde_json::Value::from(20_u64);
    metadata["content_digest"] = serde_json::Value::String("legacy".to_owned());
    fs::write(marker, serde_json::to_vec(&metadata).unwrap()).unwrap();

    assert!(cached(&fetcher, &dependency).is_some());
}

#[test]
fn malformed_completion_marker_is_rejected() {
    let (_cache, fetcher, dependency) = cached_fixture();
    fs::write(
        destination(&fetcher, &dependency).join(COMPLETION_MARKER),
        b"{}",
    )
    .unwrap();

    let destination = destination(&fetcher, &dependency);
    assert!(matches!(
        fetcher
            .cached(&dependency, &acquisition(&fetcher, &dependency))
            .unwrap(),
        CacheLookup::InvalidEntry
    ));
    assert!(!destination.exists());
}

#[cfg(unix)]
#[test]
fn symlinked_cached_artifact_is_not_followed() {
    use std::os::unix::fs::symlink;

    let (cache, fetcher, dependency) = cached_fixture();
    let artifact = destination(&fetcher, &dependency).join(CACHED_ARTIFACT);
    let outside = cache.path().join("outside.tgz");
    fs::write(&outside, fixture_archive()).unwrap();
    fs::remove_file(&artifact).unwrap();
    symlink(&outside, &artifact).unwrap();

    assert!(cached(&fetcher, &dependency).is_none());
    assert!(outside.is_file());
}

#[cfg(unix)]
#[test]
fn cached_fifo_is_rejected_without_blocking() {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};

    let (_cache, fetcher, dependency) = cached_fixture();
    let artifact = destination(&fetcher, &dependency).join(CACHED_ARTIFACT);
    fs::remove_file(&artifact).unwrap();
    let path = CString::new(artifact.as_os_str().as_bytes()).unwrap();
    // SAFETY: `path` is NUL-terminated and points to a test-owned cache entry.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);

    assert!(cached(&fetcher, &dependency).is_none());
}
