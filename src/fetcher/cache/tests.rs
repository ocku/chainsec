use std::fs;

use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use flate2::{Compression, write::GzEncoder};
use sha2::{Digest, Sha256, Sha512};
use url::Url;

use crate::{
    error::{Error, Result},
    model::{Dependency, Ecosystem, FetchMetadata},
};

use super::storage::lock_entry;

fn acquisition(fetcher: &SourceFetcher, dependency: &Dependency) -> Acquisition {
    fetcher.acquisition(dependency).unwrap()
}

fn destination(fetcher: &SourceFetcher, dependency: &Dependency) -> PathBuf {
    acquisition(fetcher, dependency).destination
}

fn cached(fetcher: &SourceFetcher, dependency: &Dependency) -> Option<FetchMetadata> {
    let acquisition = acquisition(fetcher, dependency);
    match fetcher.cached(dependency, &acquisition).unwrap() {
        CacheLookup::Hit(metadata) => Some(metadata),
        CacheLookup::Miss | CacheLookup::InvalidEntry => None,
    }
}

fn write_deno_module(source: &Path, url: &Url, bytes: &[u8]) {
    fs::create_dir_all(source).unwrap();
    let filename = format!(
        "{}.ts",
        hex::encode(Sha256::digest(url.to_string().as_bytes()))
    );
    fs::write(source.join(filename), bytes).unwrap();
}

#[derive(Clone, Copy)]
enum IntegrityAlgorithm {
    Sha256,
    Sha512,
}

fn fixture_archive() -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    let contents = b"module.exports = 1;\n";
    let mut header = tar::Header::new_gnu();
    header.set_mode(0o644);
    header.set_size(contents.len() as u64);
    header.set_cksum();
    archive
        .append_data(&mut header, "package/index.js", contents.as_slice())
        .unwrap();
    archive.finish().unwrap();
    archive.into_inner().unwrap().finish().unwrap()
}

fn integrity(algorithm: IntegrityAlgorithm, archive: &[u8]) -> String {
    match algorithm {
        IntegrityAlgorithm::Sha256 => {
            format!("sha256:{}", hex::encode(Sha256::digest(archive)))
        }
        IntegrityAlgorithm::Sha512 => {
            format!("sha512-{}", STANDARD.encode(Sha512::digest(archive)))
        }
    }
}

fn cached_fixture() -> (tempfile::TempDir, SourceFetcher, Dependency) {
    cached_fixture_with_integrity(IntegrityAlgorithm::Sha256)
}

fn cached_fixture_with_integrity(
    algorithm: IntegrityAlgorithm,
) -> (tempfile::TempDir, SourceFetcher, Dependency) {
    let cache = tempfile::tempdir().unwrap();
    let fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        super::super::FetchPolicy::default(),
        crate::model::EngineLimits::default(),
    )
    .unwrap();
    let archive = fixture_archive();
    let mut dependency = Dependency::declared(Ecosystem::Npm, "fixture", "1.0.0");
    dependency.resolved_version = Some("1.0.0".to_owned());
    dependency.integrity = Some(integrity(algorithm, &archive));
    dependency.source_url = Some("https://example.test/fixture.tgz".to_owned());

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
            &Url::parse("https://example.test/fixture.tgz").unwrap(),
            format!("sha256:{}", hex::encode(Sha256::digest(&archive))),
            &temporary,
            &source,
        )
        .unwrap();

    let cached = cached(&fetcher, &dependency).unwrap();
    assert!(cached.cache_hit);
    assert!(!cached.source.starts_with(cache.path().join("cache")));
    assert_eq!(
        fs::read(cached.source.join("index.js")).unwrap(),
        b"module.exports = 1;\n"
    );
    (cache, fetcher, dependency)
}

#[cfg(unix)]
#[test]
fn rejects_a_preexisting_cache_root_with_unsafe_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let parent = tempfile::tempdir().unwrap();
    let cache = parent.path().join("cache");
    fs::create_dir(&cache).unwrap();
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o777)).unwrap();

    let error = match SourceFetcher::new(
        cache,
        super::super::FetchPolicy::default(),
        crate::model::EngineLimits::default(),
    ) {
        Ok(_) => panic!("unsafe cache root was accepted"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("not be group- or world-writable")
    );
}

#[cfg(unix)]
#[test]
fn rejects_a_preexisting_ecosystem_directory_with_unsafe_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let parent = tempfile::tempdir().unwrap();
    let cache = parent.path().join("cache");
    fs::create_dir(&cache).unwrap();
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(cache.join("npm")).unwrap();
    fs::set_permissions(cache.join("npm"), fs::Permissions::from_mode(0o777)).unwrap();
    let fetcher = SourceFetcher::new(
        cache,
        super::super::FetchPolicy::default(),
        crate::model::EngineLimits::default(),
    )
    .unwrap();
    let dependency = Dependency::declared(Ecosystem::Npm, "fixture", "1.0.0");

    let error = match fetcher.acquisition(&dependency) {
        Ok(_) => panic!("unsafe ecosystem directory was accepted"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("not be group- or world-writable")
    );
}

#[cfg(unix)]
#[test]
fn rejects_a_preexisting_cache_lock_directory_with_unsafe_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let parent = tempfile::tempdir().unwrap();
    let cache = parent.path().join("cache");
    let locks = parent.path().join("cache.locks");
    fs::create_dir(&locks).unwrap();
    fs::set_permissions(&locks, fs::Permissions::from_mode(0o770)).unwrap();

    let error = match SourceFetcher::new(
        cache,
        super::super::FetchPolicy::default(),
        crate::model::EngineLimits::default(),
    ) {
        Ok(_) => panic!("unsafe lock directory was accepted"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("mode 0700"));
}

#[cfg(unix)]
#[test]
fn rejects_a_multiply_linked_cache_lock_file() {
    use std::os::unix::fs::PermissionsExt;

    let parent = tempfile::tempdir().unwrap();
    let cache = parent.path().join("cache");
    let locks = parent.path().join("cache.locks");
    fs::create_dir(&locks).unwrap();
    fs::set_permissions(&locks, fs::Permissions::from_mode(0o700)).unwrap();
    let lifecycle = locks.join("lifecycle.lock");
    fs::write(&lifecycle, b"").unwrap();
    fs::set_permissions(&lifecycle, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&lifecycle, locks.join("alias.lock")).unwrap();

    let error = match SourceFetcher::new(
        cache,
        super::super::FetchPolicy::default(),
        crate::model::EngineLimits::default(),
    ) {
        Ok(_) => panic!("multiply linked lock file was accepted"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("have one link"));
}

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
        super::super::FetchPolicy::default(),
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
        super::super::FetchPolicy::default(),
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
        super::super::FetchPolicy::default(),
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
fn concurrent_fetchers_can_create_a_fresh_cache() {
    let temporary = tempfile::tempdir().unwrap();
    let cache = temporary.path().join("cache");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let fetchers = (0..8)
        .map(|_| {
            let barrier = barrier.clone();
            let cache = cache.clone();
            std::thread::spawn(move || {
                barrier.wait();
                SourceFetcher::new(
                    cache,
                    super::super::FetchPolicy::default(),
                    crate::model::EngineLimits::default(),
                )
                .map(|_| ())
            })
        })
        .collect::<Vec<_>>();

    for fetcher in fetchers {
        fetcher.join().unwrap().unwrap();
    }
    assert!(
        temporary
            .path()
            .join("cache.locks/lifecycle.lock")
            .is_file()
    );
    assert!(fs::read_dir(&cache).unwrap().next().is_none());
}

#[cfg(unix)]
#[test]
fn cache_root_replacement_remains_confined_to_the_pinned_root() {
    let temporary = tempfile::tempdir().unwrap();
    let cache = temporary.path().join("cache");
    let original = temporary.path().join("cache-original");
    let outside = temporary.path().join("outside");
    let fetcher = SourceFetcher::new(
        cache.clone(),
        super::super::FetchPolicy::default(),
        crate::model::EngineLimits::default(),
    )
    .unwrap();
    let dependency = Dependency::declared(Ecosystem::Npm, "fixture", "1.0.0");

    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("sentinel"), "outside").unwrap();
    fs::rename(&cache, &original).unwrap();
    fs::create_dir(&cache).unwrap();

    let acquisition = fetcher.acquisition(&dependency).unwrap();
    assert!(original.join("npm").is_dir());
    assert!(!cache.join("npm").exists());
    assert_eq!(
        fs::read_to_string(outside.join("sentinel")).unwrap(),
        "outside"
    );
    assert!(!acquisition.destination.exists());
}

#[cfg(unix)]
#[test]
fn symlinked_cache_root_is_rejected() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().unwrap();
    let outside = temporary.path().join("outside");
    let cache = temporary.path().join("cache");
    fs::create_dir(&outside).unwrap();
    symlink(&outside, &cache).unwrap();

    assert!(matches!(
        SourceFetcher::new(
            cache,
            super::super::FetchPolicy::default(),
            crate::model::EngineLimits::default(),
        ),
        Err(Error::Policy { .. })
    ));
    assert!(fs::read_dir(outside).unwrap().next().is_none());
}

#[cfg(unix)]
#[test]
fn symlinked_dependency_lock_is_rejected() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().unwrap();
    let cache = temporary.path().join("cache");
    let outside = temporary.path().join("outside");
    let fetcher = SourceFetcher::new(
        cache,
        super::super::FetchPolicy::default(),
        crate::model::EngineLimits::default(),
    )
    .unwrap();
    let mut dependency = Dependency::declared(Ecosystem::Npm, "fixture", "1.0.0");
    dependency.resolved_version = Some("1.0.0".to_owned());
    dependency.integrity = Some("sha256:fixture".to_owned());
    let acquisition = acquisition(&fetcher, &dependency);
    let locks = &fetcher.cache_lock_directory;
    fs::write(&outside, "do not open through the cache").unwrap();
    symlink(
        &outside,
        locks.join(format!("{}.lock", acquisition.identity)),
    )
    .unwrap();

    assert!(matches!(
        lock_entry(&acquisition),
        Err(Error::Policy { .. })
    ));
    assert!(matches!(
        fetcher.cached(&dependency, &acquisition),
        Err(Error::Policy { .. })
    ));
    assert_eq!(
        fs::read_to_string(outside).unwrap(),
        "do not open through the cache"
    );
}

#[cfg(unix)]
#[test]
fn symlinked_ecosystem_cache_is_rejected() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().unwrap();
    let cache = temporary.path().join("cache");
    let outside = temporary.path().join("outside");
    let fetcher = SourceFetcher::new(
        cache.clone(),
        super::super::FetchPolicy::default(),
        crate::model::EngineLimits::default(),
    )
    .unwrap();
    fs::create_dir(&outside).unwrap();
    symlink(&outside, cache.join("npm")).unwrap();
    let mut dependency = Dependency::declared(Ecosystem::Npm, "fixture", "1.0.0");
    dependency.resolved_version = Some("1.0.0".to_owned());
    dependency.integrity = Some("sha256:fixture".to_owned());

    assert!(matches!(
        fetcher.acquisition(&dependency),
        Err(Error::Policy { .. })
    ));
    assert!(fs::read_dir(outside).unwrap().next().is_none());
}

#[test]
fn missing_cache_purge_does_not_create_coordination_metadata() {
    let temporary = tempfile::tempdir().unwrap();
    let parent = temporary.path().join("missing");
    let cache = parent.join("cache");

    assert!(!purge_cache(&cache).unwrap());
    assert!(!parent.exists());
}

#[test]
fn cache_purge_rejects_parent_directory_aliases() {
    let temporary = tempfile::tempdir().unwrap();
    let cache = temporary.path().join("cache");
    let protected = temporary.path().join("must-not-delete");
    fs::create_dir(&cache).unwrap();
    fs::write(&protected, "protected").unwrap();

    assert!(matches!(
        purge_cache(&cache.join("..")),
        Err(Error::InvalidConfiguration { .. })
    ));
    assert_eq!(fs::read_to_string(protected).unwrap(), "protected");
}

#[test]
fn cache_purge_waits_for_active_fetchers() {
    let temporary = tempfile::tempdir().unwrap();
    let cache = temporary.path().join("cache");
    let fetcher = SourceFetcher::new(
        cache.clone(),
        super::super::FetchPolicy::default(),
        crate::model::EngineLimits::default(),
    )
    .unwrap();
    fs::create_dir(cache.join("npm")).unwrap();
    fs::write(cache.join("npm/package"), "cached").unwrap();
    let workspace = fetcher.create_workspace_directory().unwrap();
    fetcher.retain_workspace(workspace.clone());

    let (started_sender, started_receiver) = std::sync::mpsc::channel();
    let (finished_sender, finished_receiver) = std::sync::mpsc::channel();
    let purge_cache_path = cache.clone();
    let purge = std::thread::spawn(move || {
        started_sender.send(()).unwrap();
        let result = purge_cache(&purge_cache_path);
        finished_sender.send(result).unwrap();
    });
    started_receiver.recv().unwrap();
    assert!(
        finished_receiver
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err()
    );

    drop(fetcher);
    assert!(
        finished_receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap()
            .unwrap()
    );
    purge.join().unwrap();

    assert!(!workspace.exists());
    assert!(!cache.join("npm").exists());
    assert!(
        temporary
            .path()
            .join("cache.locks/lifecycle.lock")
            .is_file()
    );
    assert!(fs::read_dir(&cache).unwrap().next().is_none());
}

#[test]
fn cache_purge_removes_stale_entry_locks_but_preserves_lifecycle_lock() {
    let temporary = tempfile::tempdir().unwrap();
    let cache = temporary.path().join("cache");
    let fetcher = SourceFetcher::new(
        cache.clone(),
        super::super::FetchPolicy::default(),
        crate::model::EngineLimits::default(),
    )
    .unwrap();
    let locks = temporary.path().join("cache.locks");
    let stale_lock = format!("{}.lock", "a".repeat(64));
    fs::write(locks.join(&stale_lock), "").unwrap();
    fs::write(locks.join("unrelated.lock"), "").unwrap();
    fs::write(locks.join("keep.txt"), "").unwrap();
    drop(fetcher);

    assert!(purge_cache(&cache).unwrap());

    assert!(!locks.join(stale_lock).exists());
    assert!(locks.join("lifecycle.lock").is_file());
    assert!(locks.join("unrelated.lock").is_file());
    assert!(locks.join("keep.txt").is_file());
}

#[test]
fn cache_purge_removes_abandoned_staging_directories() {
    let temporary = tempfile::tempdir().unwrap();
    let cache = temporary.path().join("cache");
    fs::create_dir_all(cache.join(".tmp-abandoned/source")).unwrap();
    fs::write(cache.join(".tmp-abandoned/source/package.js"), "cached").unwrap();
    fs::create_dir(cache.join(".invalid-cache-entry-abandoned")).unwrap();
    fs::write(
        cache.join(".invalid-cache-entry-abandoned/.artifact"),
        "cached",
    )
    .unwrap();

    assert!(purge_cache(&cache).unwrap());

    assert!(!cache.join(".tmp-abandoned").exists());
    assert!(!cache.join(".invalid-cache-entry-abandoned").exists());
    assert!(
        temporary
            .path()
            .join("cache.locks/lifecycle.lock")
            .is_file()
    );
}

#[test]
fn cache_identity_cannot_confuse_field_contents_with_field_boundaries() {
    let cache = tempfile::tempdir().unwrap();
    let fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        super::super::FetchPolicy::default(),
        crate::model::EngineLimits::default(),
    )
    .unwrap();
    let source_url = "https://example.test/shared.tgz";
    let mut embedded = Dependency::declared(Ecosystem::Npm, "shared", "1.0.0");
    embedded.resolved_version = Some("1.0.0".to_owned());
    embedded.integrity = Some(format!("sha512-shared\0source-url\0{source_url}"));
    let mut separate = Dependency::declared(Ecosystem::Npm, "shared", "1.0.0");
    separate.resolved_version = Some("1.0.0".to_owned());
    separate.integrity = Some("sha512-shared".to_owned());
    separate.source_url = Some(source_url.to_owned());

    // The previous delimiter-based encoding produced identical inputs for these values.
    assert_ne!(
        destination(&fetcher, &embedded),
        destination(&fetcher, &separate)
    );
}

#[test]
fn cache_identity_distinguishes_pinned_source_urls() {
    let cache = tempfile::tempdir().unwrap();
    let fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        super::super::FetchPolicy::default(),
        crate::model::EngineLimits::default(),
    )
    .unwrap();
    let mut first = Dependency::declared(Ecosystem::Npm, "shared", "1.0.0");
    first.resolved_version = Some("1.0.0".to_owned());
    first.integrity = Some("sha512-shared".to_owned());
    first.source_url = Some("https://first.example.test/shared.tgz".to_owned());
    let mut second = first.clone();
    second.source_url = Some("https://second.example.test/shared.tgz".to_owned());

    assert_ne!(
        destination(&fetcher, &first),
        destination(&fetcher, &second)
    );
}

#[test]
fn deno_graph_cache_identity_uses_discovered_lockfile_snapshot() {
    let cache = tempfile::tempdir().unwrap();
    let fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        super::super::FetchPolicy::default(),
        crate::model::EngineLimits::default(),
    )
    .unwrap();
    let project = cache.path().join("project");
    fs::create_dir(&project).unwrap();
    let url = "https://example.test/shared.ts";
    fs::write(
        project.join("deno.json"),
        format!(r#"{{"imports":{{"shared":"{url}"}}}}"#),
    )
    .unwrap();
    fs::write(
        project.join("deno.lock"),
        format!(r#"{{"version":"4","remote":{{"{url}":"sha256:shared"}}}}"#),
    )
    .unwrap();
    let dependency = crate::manifests::discover(&project)
        .unwrap()
        .dependencies
        .into_iter()
        .find(|dependency| dependency.requirement == url)
        .unwrap();

    let original = destination(&fetcher, &dependency);
    fs::write(
        project.join("deno.lock"),
        format!(r#"{{"version":"4","remote":{{"{url}":"sha256:changed"}}}}"#),
    )
    .unwrap();

    assert_eq!(original, destination(&fetcher, &dependency));
}

#[test]
fn lockfile_replacement_after_preparation_cannot_change_deno_graph_snapshot() {
    let cache = tempfile::tempdir().unwrap();
    let fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        super::super::FetchPolicy::default(),
        crate::model::EngineLimits::default(),
    )
    .unwrap();
    let root = Url::parse("https://example.test/root.ts").unwrap();
    let child = Url::parse("https://example.test/child.ts").unwrap();
    let root_bytes = b"import './child.ts';\n";
    let child_a = b"export const version = 'A';\n";
    let child_b = b"export const version = 'B';\n";
    let root_integrity = format!("sha256:{}", hex::encode(Sha256::digest(root_bytes)));
    let child_a_integrity = format!("sha256:{}", hex::encode(Sha256::digest(child_a)));
    let child_b_integrity = format!("sha256:{}", hex::encode(Sha256::digest(child_b)));
    let lockfile = cache.path().join("deno.lock");
    let lock = |child_integrity: &str| {
        format!(
            r#"{{"version":"4","remote":{{"{root}":"{root_integrity}","{child}":"{child_integrity}"}}}}"#
        )
    };
    let initial_lockfile = lock(&child_a_integrity);
    fs::write(&lockfile, &initial_lockfile).unwrap();

    let mut dependency = Dependency::declared(Ecosystem::Deno, "root", root.to_string());
    dependency.resolved_version = Some(root.to_string());
    dependency.integrity = Some(root_integrity.clone());
    dependency.source_url = Some(root.to_string());
    dependency.lockfile = Some(lockfile.clone());
    dependency.deno_lockfile_snapshot = Some(crate::model::DenoLockfileSnapshot::from_lockfile(
        initial_lockfile.as_bytes(),
        &serde_json::from_str(&initial_lockfile).unwrap(),
    ));
    let package_id = dependency.id();

    let prepared =
        crate::fetcher::Fetcher::prepare_fetch(&fetcher, dependency.clone(), PathBuf::new())
            .unwrap();
    let prepared_identity = prepared.acquisition_identity.clone().unwrap();
    let acquisition_a = prepared.acquisition.unwrap();
    fs::write(&lockfile, lock(&child_b_integrity)).unwrap();
    assert_eq!(dependency.id(), package_id);

    let downloaded = cache.path().join("downloaded-under-a");
    write_deno_module(&downloaded, &root, root_bytes);
    write_deno_module(&downloaded, &child, child_a);
    let temporary = cache.path().join("temporary-a");
    fs::create_dir(&temporary).unwrap();
    let (source, digest, _) = fetcher
        .rebuild_cached_deno_graph(
            &root,
            &temporary,
            dependency.integrity.as_deref(),
            acquisition_a.deno_lockfile.as_ref(),
            &downloaded,
        )
        .unwrap();
    fetcher
        .publish(
            &dependency,
            &acquisition_a,
            &root,
            digest,
            &temporary,
            &source,
        )
        .unwrap();

    let acquisition_b = acquisition(&fetcher, &dependency);
    assert_eq!(prepared_identity, acquisition_a.identity);
    assert_eq!(acquisition_a.identity, acquisition_b.identity);
    assert_eq!(acquisition_a.destination, acquisition_b.destination);
    assert!(acquisition_a.destination.is_dir());
    assert!(matches!(
        fetcher.cached(&dependency, &acquisition_a).unwrap(),
        CacheLookup::Hit(_)
    ));
    assert!(matches!(
        fetcher.cached(&dependency, &acquisition_b).unwrap(),
        CacheLookup::Hit(_)
    ));
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
