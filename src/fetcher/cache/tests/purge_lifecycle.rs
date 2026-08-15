use super::*;

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
                    super::super::super::FetchPolicy::default(),
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
        super::super::super::FetchPolicy::default(),
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
        super::super::super::FetchPolicy::default(),
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
