use super::*;

#[tokio::test]
async fn single_fetch_concurrency_uses_configured_analysis_threads() {
    let (root, packages) = parallel_fetch_fixture(6);
    let fetcher = ConcurrencyTrackingFixtureFetcher::new(packages.path().to_owned());

    let report = Engine::new(
        &[],
        &fetcher,
        engine_policy(EngineLimits::default(), true, true, vec![], false, false),
    )
    .with_max_analysis_threads(2)
    .analyze(root.path())
    .await
    .unwrap();

    assert!(report.issues.is_empty(), "{:?}", report.issues);
    assert_eq!(report.packages.len(), 7);
    assert_eq!(fetcher.max_active_fetches(), 2);
}

#[tokio::test]
async fn batch_fetch_concurrency_uses_configured_analysis_threads() {
    let (root, packages) = parallel_fetch_fixture(6);
    let fetcher = ConcurrencyTrackingFixtureFetcher::new(packages.path().to_owned());

    let reports = Engine::new(
        &[],
        &fetcher,
        engine_policy(EngineLimits::default(), true, true, vec![], false, false),
    )
    .with_max_analysis_threads(3)
    .analyze_fetched_roots(vec![fetched_fixture_root(
        root.path().to_owned(),
        "npm:root@1.0.0#sha512-root",
    )])
    .await
    .unwrap();

    assert_eq!(reports.len(), 1);
    assert!(reports[0].issues.is_empty(), "{:?}", reports[0].issues);
    assert_eq!(reports[0].packages.len(), 7);
    assert_eq!(fetcher.max_active_fetches(), 3);
}

#[tokio::test]
async fn shared_frontier_dependency_is_fetched_once() {
    let root = tempfile::tempdir().unwrap();
    let packages = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"dependencies":{"scan-overlap-a":"1.0.0","scan-overlap-b":"1.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("package-lock.json"),
        r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies":{"scan-overlap-a":"1.0.0","scan-overlap-b":"1.0.0"}},
                "node_modules/scan-overlap-a": {"version":"1.0.0","resolved":"https://registry.example.test/a.tgz","integrity":"sha512-a","dependencies":{"shared":"1.0.0"}},
                "node_modules/scan-overlap-b": {"version":"1.0.0","resolved":"https://registry.example.test/b.tgz","integrity":"sha512-b","dependencies":{"shared":"1.0.0"}},
                "node_modules/shared": {"version":"1.0.0","resolved":"https://registry.example.test/shared.tgz","integrity":"sha512-shared"}
            }
        }"#,
    )
    .unwrap();
    for package in ["scan-overlap-a", "scan-overlap-b", "shared"] {
        fs::create_dir(packages.path().join(package)).unwrap();
    }
    for package in ["scan-overlap-a", "scan-overlap-b"] {
        fs::write(
            packages.path().join(package).join("package.json"),
            r#"{"dependencies":{"shared":"1.0.0"}}"#,
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
    let report = Engine::new(
        &[],
        &fetcher,
        engine_policy(EngineLimits::default(), true, true, vec![], false, false),
    )
    .analyze(root.path())
    .await
    .unwrap();

    assert!(report.issues.is_empty(), "{:?}", report.issues);
    assert_eq!(
        fetches
            .lock()
            .unwrap()
            .get("npm:shared@1.0.0#sha512-shared"),
        Some(&1),
        "shared dependency should be fetched once for its frontier"
    );
}

fn parallel_fetch_fixture(package_count: usize) -> (tempfile::TempDir, tempfile::TempDir) {
    let root = tempfile::tempdir().unwrap();
    let packages = tempfile::tempdir().unwrap();
    let mut dependencies = serde_json::Map::new();
    let mut lock_packages = serde_json::Map::new();

    for index in 0..package_count {
        let package = format!("parallel-{index}");
        dependencies.insert(package.clone(), serde_json::json!("1.0.0"));
        lock_packages.insert(
            format!("node_modules/{package}"),
            serde_json::json!({
                "version": "1.0.0",
                "resolved": format!("https://registry.example.test/{package}.tgz"),
                "integrity": format!("sha512-{package}"),
            }),
        );
        fs::create_dir(packages.path().join(&package)).unwrap();
        fs::write(
            packages.path().join(&package).join("package.json"),
            format!(r#"{{"name":"{package}","version":"1.0.0"}}"#),
        )
        .unwrap();
    }

    lock_packages.insert(
        String::new(),
        serde_json::json!({"dependencies": dependencies.clone()}),
    );
    fs::write(
        root.path().join("package.json"),
        serde_json::to_vec(&serde_json::json!({"dependencies": dependencies})).unwrap(),
    )
    .unwrap();
    fs::write(
        root.path().join("package-lock.json"),
        serde_json::to_vec(&serde_json::json!({
            "lockfileVersion": 3,
            "packages": lock_packages,
        }))
        .unwrap(),
    )
    .unwrap();

    (root, packages)
}
