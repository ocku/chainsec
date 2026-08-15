use super::*;

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
        super::super::super::FetchPolicy::default(),
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
        super::super::super::FetchPolicy::default(),
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
        super::super::super::FetchPolicy::default(),
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
        super::super::super::FetchPolicy::default(),
        crate::model::EngineLimits::default(),
    ) {
        Ok(_) => panic!("multiply linked lock file was accepted"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("have one link"));
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
        super::super::super::FetchPolicy::default(),
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
            super::super::super::FetchPolicy::default(),
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
        super::super::super::FetchPolicy::default(),
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
        super::super::super::FetchPolicy::default(),
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
