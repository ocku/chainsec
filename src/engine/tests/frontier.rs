use super::*;

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
        EngineLimits::default(),
        true,
        true,
        vec![],
        false,
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
