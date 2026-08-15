use super::*;

#[test]
fn cache_identity_cannot_confuse_field_contents_with_field_boundaries() {
    let cache = tempfile::tempdir().unwrap();
    let fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        super::super::super::FetchPolicy::default(),
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
        super::super::super::FetchPolicy::default(),
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
fn cache_identity_canonicalizes_equivalent_pinned_source_urls() {
    let cache = tempfile::tempdir().unwrap();
    let fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        super::super::super::FetchPolicy::default(),
        crate::model::EngineLimits::default(),
    )
    .unwrap();
    let mut noncanonical = Dependency::declared(Ecosystem::Npm, "shared", "1.0.0");
    noncanonical.resolved_version = Some("1.0.0".to_owned());
    noncanonical.integrity = Some("sha512-shared".to_owned());
    noncanonical.source_url =
        Some("HTTPS://EXAMPLE.TEST:443/releases/./old/../shared.tgz".to_owned());
    let mut canonical = noncanonical.clone();
    canonical.source_url = Some("https://example.test/releases/shared.tgz".to_owned());

    assert_eq!(
        destination(&fetcher, &noncanonical),
        destination(&fetcher, &canonical)
    );
}

#[test]
fn cache_identity_keeps_meaningfully_distinct_url_paths_separate() {
    let cache = tempfile::tempdir().unwrap();
    let fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        super::super::super::FetchPolicy::default(),
        crate::model::EngineLimits::default(),
    )
    .unwrap();
    let mut first = Dependency::declared(Ecosystem::Npm, "shared", "1.0.0");
    first.resolved_version = Some("1.0.0".to_owned());
    first.integrity = Some("sha512-shared".to_owned());
    first.source_url = Some("https://example.test/releases/shared.tgz".to_owned());
    let mut second = first.clone();
    second.source_url = Some("https://example.test/releases/Shared.tgz".to_owned());

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
        super::super::super::FetchPolicy::default(),
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
        super::super::super::FetchPolicy::default(),
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
