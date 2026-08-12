use super::*;

#[tokio::test]
async fn fetched_root_batch_allows_one_shared_dependency_within_aggregate_limit() {
    let packages = tempfile::tempdir().unwrap();
    for package in ["root-a", "root-b", "shared"] {
        fs::create_dir(packages.path().join(package)).unwrap();
    }
    for root in ["root-a", "root-b"] {
        fs::write(
            packages.path().join(root).join("package.json"),
            r#"{"dependencies":{"shared":"1.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            packages.path().join(root).join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies":{"shared":"1.0.0"}},
                    "node_modules/shared": {"version":"1.0.0","resolved":"https://registry.example.test/shared.tgz","integrity":"sha512-shared"}
                }
            }"#,
        )
        .unwrap();
    }
    fs::write(
        packages.path().join("shared/package.json"),
        r#"{"name":"shared","version":"1.0.0"}"#,
    )
    .unwrap();

    let fetches = Arc::new(Mutex::new(HashMap::new()));
    let fetcher = CountingFixtureFetcher {
        packages: packages.path().to_owned(),
        fetches: Arc::clone(&fetches),
    };
    let limits = EngineLimits {
        max_packages: 3,
        ..EngineLimits::default()
    };
    let reports = Engine::new(&[], &fetcher, limits, true, true, vec![], false)
        .analyze_fetched_roots(vec![
            fetched_fixture_root(
                packages.path().join("root-a"),
                "npm:root-a@1.0.0#sha512-root-a",
            ),
            fetched_fixture_root(
                packages.path().join("root-b"),
                "npm:root-b@1.0.0#sha512-root-b",
            ),
        ])
        .await
        .unwrap();

    assert_eq!(
        fetches
            .lock()
            .unwrap()
            .get("npm:shared@1.0.0#sha512-shared"),
        Some(&1)
    );
    for report in reports {
        assert!(report.issues.is_empty(), "{:?}", report.issues);
        assert_eq!(report.packages.len(), 2);
    }
}

#[tokio::test]
async fn fetched_root_batch_rejects_a_frontier_that_exceeds_aggregate_limit() {
    let packages = tempfile::tempdir().unwrap();
    for package in ["root-a", "root-b", "only-a", "only-b"] {
        fs::create_dir(packages.path().join(package)).unwrap();
    }
    for (root, dependency) in [("root-a", "only-a"), ("root-b", "only-b")] {
        fs::write(
            packages.path().join(root).join("package.json"),
            format!(r#"{{"dependencies":{{"{dependency}":"1.0.0"}}}}"#),
        )
        .unwrap();
        fs::write(
            packages.path().join(root).join("package-lock.json"),
            format!(
                r#"{{
                    "lockfileVersion": 3,
                    "packages": {{
                        "": {{"dependencies":{{"{dependency}":"1.0.0"}}}},
                        "node_modules/{dependency}": {{"version":"1.0.0","resolved":"https://registry.example.test/{dependency}.tgz","integrity":"sha512-{dependency}"}}
                    }}
                }}"#
            ),
        )
        .unwrap();
        fs::write(
            packages.path().join(dependency).join("package.json"),
            format!(r#"{{"name":"{dependency}","version":"1.0.0"}}"#),
        )
        .unwrap();
    }

    let fetches = Arc::new(Mutex::new(HashMap::new()));
    let fetcher = CountingFixtureFetcher {
        packages: packages.path().to_owned(),
        fetches: Arc::clone(&fetches),
    };
    let limits = EngineLimits {
        max_packages: 3,
        ..EngineLimits::default()
    };
    let reports = Engine::new(&[], &fetcher, limits, true, true, vec![], false)
        .analyze_fetched_roots(vec![
            fetched_fixture_root(
                packages.path().join("root-a"),
                "npm:root-a@1.0.0#sha512-root-a",
            ),
            fetched_fixture_root(
                packages.path().join("root-b"),
                "npm:root-b@1.0.0#sha512-root-b",
            ),
        ])
        .await
        .unwrap();

    assert!(fetches.lock().unwrap().is_empty());
    for report in reports {
        assert_eq!(report.packages.len(), 1);
        assert!(report.issues.iter().any(|issue| {
            issue.fatal
                && issue.operation == "batch traversal"
                && issue.message.contains("batch packages")
        }));
    }
}
