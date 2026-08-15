use super::{support::*, *};

#[test]
fn selects_highest_non_yanked_jsr_release_matching_requirement() {
    let dependency = Dependency::declared(Ecosystem::Deno, "assert", "jsr:@std/assert@^1.0.0");
    let metadata = serde_json::json!({
        "versions": {
            "1.0.0": {},
            "1.2.0": {},
            "1.3.0": { "yanked": true },
            "2.0.0": {}
        }
    });

    assert_eq!(
        select_jsr_version(&dependency, "^1.0.0", &metadata).unwrap(),
        "1.2.0"
    );
}

#[test]
fn parses_unversioned_scoped_jsr_package() {
    let dependency = Dependency::declared(Ecosystem::Deno, "assert", "jsr:@std/assert");

    assert_eq!(
        jsr_package_and_requirement(&dependency).unwrap(),
        ("@std/assert", "*")
    );
}

#[test]
fn parses_jsr_entrypoint_specifiers_without_including_them_in_the_version_requirement() {
    for (requirement, expected_requirement) in
        [("jsr:@std/path@1/join", "1"), ("jsr:@std/path/join", "*")]
    {
        let dependency = Dependency::declared(Ecosystem::Deno, "path", requirement);
        assert_eq!(
            jsr_package_and_requirement(&dependency).unwrap(),
            ("@std/path", expected_requirement)
        );
    }
}

#[test]
fn rejects_empty_explicit_jsr_version_requirement() {
    let dependency = Dependency::declared(Ecosystem::Deno, "assert", "jsr:@std/assert@");

    assert!(
        jsr_package_and_requirement(&dependency)
            .unwrap_err()
            .to_string()
            .contains("cannot be empty")
    );
}

#[test]
fn rejects_malformed_jsr_release_metadata() {
    let dependency = Dependency::declared(Ecosystem::Deno, "assert", "jsr:@std/assert");
    for metadata in [
        serde_json::json!({ "versions": { "1.0.0": null } }),
        serde_json::json!({ "versions": { "1.0.0": { "yanked": "yes" } } }),
    ] {
        assert!(
            select_jsr_version(&dependency, "*", &metadata)
                .unwrap_err()
                .to_string()
                .contains("invalid JSR")
        );
    }
}

#[tokio::test]
async fn allow_unlocked_does_not_unlock_discovered_jsr_but_remote_roots_still_resolve() {
    let (base_url, stop, requests, server) =
        spawn_jsr_registry(serde_json::json!({ "versions": { "1.0.0": {} } }), &[], &[]);
    let (cache, mut fetcher) = jsr_fetcher(&base_url, 3);
    fetcher.policy.allow_unlocked = true;
    let dependency = Dependency::declared(Ecosystem::Deno, "@std/assert", "jsr:@std/assert");

    let error = crate::fetcher::Fetcher::fetch(
        &fetcher,
        dependency.clone(),
        cache.path().join("deno.json"),
    )
    .await
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("dependency has no locked version and integrity")
    );
    assert!(requests.lock().unwrap().is_empty());

    let fetched = fetcher.fetch_remote_root(dependency).await.unwrap();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    assert!(fetched.source.is_dir());
    assert!(!requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn jsr_requests_use_a_non_html_accept_header() {
    let (base_url, stop, requests, server) =
        spawn_jsr_registry(serde_json::json!({ "versions": { "1.0.0": {} } }), &[], &[]);
    let (_cache, fetcher) = jsr_fetcher(&base_url, 3);
    let mut dependency = Dependency::declared(Ecosystem::Deno, "@std/assert", "jsr:@std/assert");

    fetcher.resolve_unlocked_jsr(&mut dependency).await.unwrap();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    for (_, request) in requests.iter() {
        let request = request.to_ascii_lowercase();
        assert!(request.contains("accept: */*\r\n"));
        assert!(!request.contains("accept: text/html"));
        assert!(!request.contains("sec-fetch-dest: document"));
    }
}

#[tokio::test]
async fn last_selection_skips_an_unavailable_newest_jsr_version() {
    let (base_url, stop, requests, server) = spawn_jsr_registry(
        serde_json::json!({
            "versions": {"3.0.0": {}, "2.0.0": {}, "1.0.0": {}}
        }),
        &["3.0.0"],
        &[],
    );
    let (_cache, fetcher) = jsr_fetcher(&base_url, 3);
    let dependency = Dependency::declared(Ecosystem::Deno, "@std/assert", "jsr:@std/assert");

    let versions = fetcher
        .resolve_jsr_version_selection(dependency, RemoteVersionSelection::Last(2))
        .await
        .unwrap();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    assert_eq!(
        versions
            .iter()
            .map(|dependency| dependency.resolved_version.as_deref().unwrap())
            .collect::<Vec<_>>(),
        ["2.0.0", "1.0.0"]
    );
    assert_eq!(
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(path, _)| path.ends_with("_meta.json"))
            .count(),
        3
    );
}

#[tokio::test]
async fn last_selection_fails_on_malformed_successful_version_metadata() {
    let (base_url, stop, requests, server) = spawn_jsr_registry(
        serde_json::json!({
            "versions": {"3.0.0": {}, "2.0.0": {}, "1.0.0": {}}
        }),
        &[],
        &["3.0.0"],
    );
    let (_cache, fetcher) = jsr_fetcher(&base_url, 3);
    let dependency = Dependency::declared(Ecosystem::Deno, "@std/assert", "jsr:@std/assert");

    let error = fetcher
        .resolve_jsr_version_selection(dependency, RemoteVersionSelection::Last(2))
        .await
        .unwrap_err();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    assert!(error.to_string().contains("invalid JSR version metadata"));
    assert_eq!(
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(path, _)| path.ends_with("_meta.json"))
            .count(),
        1
    );
}

#[tokio::test]
async fn range_selection_fails_on_malformed_historical_version_metadata() {
    let (base_url, stop, requests, server) = spawn_jsr_registry(
        serde_json::json!({
            "versions": {"3.0.0": {}, "2.0.0": {}, "1.0.0": {}}
        }),
        &[],
        &["2.0.0"],
    );
    let (_cache, fetcher) = jsr_fetcher(&base_url, 3);
    let dependency = Dependency::declared(Ecosystem::Deno, "@std/assert", "jsr:@std/assert");

    let error = fetcher
        .resolve_jsr_version_selection(
            dependency,
            RemoteVersionSelection::Range {
                from: "1.0.0".to_owned(),
                to: "3.0.0".to_owned(),
            },
        )
        .await
        .unwrap_err();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    assert!(error.to_string().contains("invalid JSR version metadata"));
    assert_eq!(
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(path, _)| path.ends_with("_meta.json"))
            .count(),
        2
    );
}

#[tokio::test]
async fn jsr_selection_stops_after_exceeding_the_root_limit() {
    let (base_url, stop, requests, server) = spawn_jsr_registry(
        serde_json::json!({
            "versions": {"3.0.0": {}, "2.0.0": {}, "1.0.0": {}}
        }),
        &[],
        &[],
    );
    let (_cache, fetcher) = jsr_fetcher(&base_url, 1);
    let dependency = Dependency::declared(Ecosystem::Deno, "@std/assert", "jsr:@std/assert");

    let error = fetcher
        .resolve_jsr_version_selection(dependency, RemoteVersionSelection::Last(3))
        .await
        .unwrap_err();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    assert_eq!(error.code(), "limit_exceeded");
    assert!(error.to_string().contains("remote version candidates"));
    assert_eq!(
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(path, _)| path.ends_with("_meta.json"))
            .count(),
        1
    );
}

#[test]
fn orders_selected_and_older_non_yanked_jsr_versions_semantically() {
    let dependency = Dependency::declared(Ecosystem::Deno, "assert", "jsr:@std/assert@latest");
    let metadata = serde_json::json!({
        "versions": {
            "10.0.0": {},
            "2.0.0": {},
            "1.10.0": { "yanked": true },
            "1.9.0": {},
            "1.2.0": {}
        }
    });

    assert_eq!(
        jsr_versions_at_or_below(&dependency, "2.0.0", &metadata).unwrap(),
        ["2.0.0", "1.9.0", "1.2.0"]
    );
}

#[test]
fn compares_exact_non_yanked_jsr_endpoints_in_to_from_order() {
    let dependency = Dependency::declared(Ecosystem::Deno, "assert", "jsr:@std/assert");
    let metadata = serde_json::json!({
        "versions": {
            "1.0.0": {},
            "1.5.0": {},
            "2.0.0": {}
        }
    });

    assert_eq!(
        jsr_compare_versions(&dependency, "1.0.0", "2.0.0", &metadata).unwrap(),
        ["2.0.0", "1.0.0"]
    );
}

#[test]
fn ranges_include_endpoints_and_exclude_yanked_jsr_intermediates() {
    let dependency = Dependency::declared(Ecosystem::Deno, "assert", "jsr:@std/assert");
    let metadata = serde_json::json!({
        "versions": {
            "0.9.0": {},
            "1.0.0": {},
            "1.4.0": { "yanked": true },
            "1.6.0": {},
            "2.0.0": {},
            "3.0.0": {}
        }
    });

    assert_eq!(
        jsr_range_versions(&dependency, "1.0.0", "2.0.0", &metadata).unwrap(),
        ["2.0.0", "1.6.0", "1.0.0"]
    );
}

#[test]
fn rejects_yanked_equal_and_reversed_jsr_endpoints() {
    let dependency = Dependency::declared(Ecosystem::Deno, "assert", "jsr:@std/assert");
    let metadata = serde_json::json!({
        "versions": {
            "1.0.0": {},
            "1.5.0": { "yanked": true },
            "2.0.0": {}
        }
    });

    assert!(
        jsr_compare_versions(&dependency, "1.5.0", "2.0.0", &metadata)
            .unwrap_err()
            .to_string()
            .contains("yanked")
    );
    assert!(
        jsr_compare_versions(&dependency, "invalid", "2.0.0", &metadata)
            .unwrap_err()
            .to_string()
            .contains("semantic version")
    );
    assert!(
        jsr_compare_versions(&dependency, "1.0.0", "1.0.0", &metadata)
            .unwrap_err()
            .to_string()
            .contains("distinct")
    );
    assert!(
        jsr_range_versions(&dependency, "2.0.0", "1.0.0", &metadata)
            .unwrap_err()
            .to_string()
            .contains("must be older")
    );
}
