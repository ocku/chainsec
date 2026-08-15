use super::{support::*, *};

#[cfg(unix)]
#[test]
fn cached_jsr_fifo_is_rejected_without_blocking() {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};

    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("cached");
    fs::create_dir(&source).unwrap();
    let relative = Path::new("nested/module.ts");
    fs::create_dir(source.join("nested")).unwrap();
    let fifo = source.join(relative);
    let fifo = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: the CString is a valid, NUL-terminated filesystem path.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

    let root = TrustedDir::open(&source).unwrap();
    assert!(matches!(
        read_cached_jsr_file(&root, &source, relative, 1024),
        Err(Error::Policy { operation, .. }) if operation == "cache validation"
    ));
}

#[tokio::test]
async fn locked_jsr_fetched_from_custom_repository_is_reused_offline() {
    let source_bytes = b"export const cached = true;\n";
    let ((base_url, stop, _requests, server), integrity) =
        spawn_jsr_package_registry(&[("mod.ts", source_bytes.as_slice())], Duration::ZERO);
    let cache = tempfile::tempdir().unwrap();
    let cache_path = cache.path().join("cache");
    let repositories = ArtifactRepositories::new(&base_url, &base_url, &base_url).unwrap();
    let online_policy = FetchPolicy {
        offline: false,
        allowed_hosts: vec!["127.0.0.1".to_owned()],
        allow_insecure_http: true,
        repositories: repositories.clone(),
        ..FetchPolicy::default()
    };
    let mut dependency = Dependency::declared(
        Ecosystem::Deno,
        "@scope/package",
        "jsr:@scope/package@1.0.0",
    );
    dependency.resolved_version = Some("1.0.0".to_owned());
    dependency.integrity = Some(integrity);
    dependency.source_url =
        Some("HTTPS://JSR.IO:443/@scope/package/releases/../1.0.0_meta.json".to_owned());
    dependency.lockfile = Some(cache.path().join("deno.lock"));

    let online =
        SourceFetcher::new(cache_path.clone(), online_policy, EngineLimits::default()).unwrap();
    let fetched = online.fetch_remote_root(dependency.clone()).await.unwrap();
    assert!(!fetched.cache_hit);
    assert_eq!(
        fetched.source_url,
        "https://jsr.io/@scope/package/1.0.0_meta.json"
    );
    assert_eq!(
        fs::read(fetched.source.join("mod.ts")).unwrap(),
        source_bytes
    );
    drop(online);
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    dependency.source_url = Some("https://jsr.io/@scope/package/1.0.0_meta.json".to_owned());
    let offline = SourceFetcher::new(
        cache_path,
        FetchPolicy {
            offline: true,
            allowed_hosts: vec!["127.0.0.1".to_owned()],
            allow_insecure_http: true,
            repositories,
            ..FetchPolicy::default()
        },
        EngineLimits::default(),
    )
    .unwrap();
    let restored = offline.fetch_remote_root(dependency).await.unwrap();

    assert!(restored.cache_hit);
    assert_eq!(
        restored.source_url,
        "https://jsr.io/@scope/package/1.0.0_meta.json"
    );
    assert_eq!(
        fs::read(restored.source.join("mod.ts")).unwrap(),
        source_bytes
    );
}
