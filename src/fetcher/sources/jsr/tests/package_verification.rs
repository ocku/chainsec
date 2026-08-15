use super::{support::*, *};

#[tokio::test]
async fn jsr_file_loop_enforces_a_per_acquisition_request_limit() {
    let files = [
        ("first.ts", b"first".as_slice()),
        ("second.ts", b"second".as_slice()),
    ];
    let ((base_url, stop, requests, server), integrity) =
        spawn_jsr_package_registry(&files, Duration::ZERO);
    let (_cache, mut fetcher) = jsr_fetcher(&base_url, 10);
    fetcher.limits.max_network_requests = 2;
    let metadata_url = fetcher
        .policy
        .repositories
        .jsr_version_metadata_url("@scope/package", "1.0.0")
        .unwrap();
    let temporary = tempfile::tempdir().unwrap();

    let error = fetcher
        .fetch_jsr_package(&metadata_url, temporary.path(), Some(&integrity))
        .await
        .unwrap_err();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    assert_eq!(error.code(), "limit_exceeded", "{error}");
    assert!(
        error
            .to_string()
            .contains("network requests per package acquisition"),
        "{error}"
    );
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn jsr_manifest_limits_are_enforced_before_downloading_source_files() {
    for (limits, expected_resource) in [
        (
            EngineLimits {
                max_extracted_files: 1,
                ..EngineLimits::default()
            },
            "extracted files",
        ),
        (
            EngineLimits {
                max_extracted_size: 10,
                ..EngineLimits::default()
            },
            "extracted bytes",
        ),
    ] {
        let files = [
            ("first.ts", b"first".as_slice()),
            ("second.ts", b"second".as_slice()),
        ];
        let ((base_url, stop, requests, server), integrity) =
            spawn_jsr_package_registry(&files, Duration::ZERO);
        let (_cache, mut fetcher) = jsr_fetcher(&base_url, 10);
        fetcher.limits = limits;
        let metadata_url = fetcher
            .policy
            .repositories
            .jsr_version_metadata_url("@scope/package", "1.0.0")
            .unwrap();
        let temporary = tempfile::tempdir().unwrap();

        let error = fetcher
            .fetch_jsr_package(&metadata_url, temporary.path(), Some(&integrity))
            .await
            .unwrap_err();
        stop.store(true, Ordering::Relaxed);
        server.join().unwrap();

        assert_eq!(error.code(), "limit_exceeded", "{error}");
        assert!(error.to_string().contains(expected_resource), "{error}");
        assert_eq!(requests.lock().unwrap().len(), 1);
        assert!(fs::read_dir(temporary.path()).unwrap().next().is_none());
    }
}

#[tokio::test]
async fn jsr_implicit_parent_directories_count_toward_the_file_limit() {
    let files = [("nested/mod.ts", b"source".as_slice())];
    let ((base_url, stop, requests, server), integrity) =
        spawn_jsr_package_registry(&files, Duration::ZERO);
    let (_cache, mut fetcher) = jsr_fetcher(&base_url, 10);
    fetcher.limits.max_extracted_files = 1;
    let metadata_url = fetcher
        .policy
        .repositories
        .jsr_version_metadata_url("@scope/package", "1.0.0")
        .unwrap();
    let temporary = tempfile::tempdir().unwrap();

    let error = fetcher
        .fetch_jsr_package(&metadata_url, temporary.path(), Some(&integrity))
        .await
        .unwrap_err();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    assert!(matches!(
        error,
        Error::LimitExceeded {
            resource,
            limit: 1
        } if resource == "extracted files"
    ));
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert!(fs::read_dir(temporary.path()).unwrap().next().is_none());
}

#[tokio::test]
async fn jsr_shared_parent_directories_are_counted_once() {
    let files = [
        ("nested/first.ts", b"first".as_slice()),
        ("nested/second.ts", b"second".as_slice()),
    ];
    let ((base_url, stop, requests, server), integrity) =
        spawn_jsr_package_registry(&files, Duration::ZERO);
    let (_cache, mut fetcher) = jsr_fetcher(&base_url, 10);
    fetcher.limits.max_extracted_files = 3;
    let metadata_url = fetcher
        .policy
        .repositories
        .jsr_version_metadata_url("@scope/package", "1.0.0")
        .unwrap();
    let temporary = tempfile::tempdir().unwrap();

    let (source, _, stats) = fetcher
        .fetch_jsr_package(&metadata_url, temporary.path(), Some(&integrity))
        .await
        .unwrap();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    assert_eq!(stats.files, 3);
    assert_eq!(stats.bytes, 11);
    assert_eq!(requests.lock().unwrap().len(), 3);
    assert_eq!(fs::read(source.join("nested/first.ts")).unwrap(), b"first");
    assert_eq!(
        fs::read(source.join("nested/second.ts")).unwrap(),
        b"second"
    );
}

#[tokio::test]
async fn jsr_file_loop_enforces_an_end_to_end_acquisition_deadline() {
    let files = [
        ("first.ts", b"first".as_slice()),
        ("second.ts", b"second".as_slice()),
    ];
    let ((base_url, stop, requests, server), integrity) =
        spawn_jsr_package_registry(&files, Duration::from_millis(40));
    let (_cache, mut fetcher) = jsr_fetcher(&base_url, 10);
    fetcher.limits.max_acquisition_duration = Duration::from_millis(70);
    let metadata_url = fetcher
        .policy
        .repositories
        .jsr_version_metadata_url("@scope/package", "1.0.0")
        .unwrap();
    let temporary = tempfile::tempdir().unwrap();

    let error = fetcher
        .fetch_jsr_package(&metadata_url, temporary.path(), Some(&integrity))
        .await
        .unwrap_err();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    assert_eq!(error.code(), "limit_exceeded", "{error}");
    assert!(
        error.to_string().contains("package acquisition seconds"),
        "{error}"
    );
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[test]
fn cached_jsr_files_are_rebuilt_only_when_bound_to_the_verified_manifest() {
    let cache = tempfile::tempdir().unwrap();
    let fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        FetchPolicy::default(),
        EngineLimits::default(),
    )
    .unwrap();
    let metadata_url = Url::parse("https://jsr.io/@scope/package/1.0.0_meta.json").unwrap();
    let source_bytes = b"export const safe = true;\n";
    let checksum = format!("sha256-{}", hex::encode(Sha256::digest(source_bytes)));
    let metadata_bytes = serde_json::to_vec(&serde_json::json!({
        "manifest": {
            "/mod.ts": {
                "size": source_bytes.len(),
                "checksum": checksum,
            }
        }
    }))
    .unwrap();
    let metadata_integrity = format!("sha256:{}", hex::encode(Sha256::digest(&metadata_bytes)));
    let cached_source = cache.path().join("cached");
    fs::create_dir(&cached_source).unwrap();
    fs::write(cached_source.join("mod.ts"), source_bytes).unwrap();

    let temporary = cache.path().join("temporary");
    fs::create_dir(&temporary).unwrap();
    let (source, _, stats) = fetcher
        .rebuild_cached_jsr_package(
            &metadata_url,
            &temporary,
            Some(&metadata_integrity),
            &metadata_bytes,
            &cached_source,
        )
        .unwrap();
    assert_eq!(stats.files, 1);
    assert_eq!(fs::read(source.join("mod.ts")).unwrap(), source_bytes);

    fs::write(
        cached_source.join("mod.ts"),
        b"export const safe = false;\n",
    )
    .unwrap();
    let tampered_temporary = cache.path().join("tampered-temporary");
    fs::create_dir(&tampered_temporary).unwrap();
    let error = fetcher
        .rebuild_cached_jsr_package(
            &metadata_url,
            &tampered_temporary,
            Some(&metadata_integrity),
            &metadata_bytes,
            &cached_source,
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("size mismatch")
            || error.to_string().contains("checksum verification failed")
    );
}
