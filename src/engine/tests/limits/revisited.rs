use super::super::*;

#[tokio::test]
async fn single_cycle_at_package_limit_still_acquires_new_package() {
    let (root, packages) = cycle_with_new_package_fixture();
    let fetches = Arc::new(Mutex::new(HashMap::new()));
    let fetcher = CountingFixtureFetcher {
        packages: packages.path().to_owned(),
        fetches: Arc::clone(&fetches),
    };

    let report = Engine::new(
        &[],
        &fetcher,
        exact_cycle_limit(),
        true,
        true,
        vec![],
        false,
        false,
    )
    .analyze(root.path())
    .await
    .unwrap();

    assert_cycle_completed_at_limit(&report, &fetches);
}

#[tokio::test]
async fn batch_cycle_at_package_limit_still_acquires_new_package() {
    let (root, packages) = cycle_with_new_package_fixture();
    let fetches = Arc::new(Mutex::new(HashMap::new()));
    let fetcher = CountingFixtureFetcher {
        packages: packages.path().to_owned(),
        fetches: Arc::clone(&fetches),
    };

    let reports = Engine::new(
        &[],
        &fetcher,
        exact_cycle_limit(),
        true,
        true,
        vec![],
        false,
        false,
    )
    .analyze_fetched_roots(vec![fetched_fixture_root(
        root.path().to_owned(),
        "npm:root@1.0.0#sha512-root",
    )])
    .await
    .unwrap();

    assert_eq!(reports.len(), 1);
    assert_cycle_completed_at_limit(&reports[0], &fetches);
}

fn cycle_with_new_package_fixture() -> (tempfile::TempDir, tempfile::TempDir) {
    let root = tempfile::tempdir().unwrap();
    let packages = tempfile::tempdir().unwrap();

    fs::write(
        root.path().join("package.json"),
        r#"{"dependencies":{"cycle-a":"1.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("package-lock.json"),
        r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies":{"cycle-a":"1.0.0"}},
                "node_modules/cycle-a": {"version":"1.0.0","resolved":"https://registry.example.test/cycle-a.tgz","integrity":"sha512-cycle-a","dependencies":{"cycle-b":"1.0.0"}},
                "node_modules/cycle-b": {"version":"1.0.0","resolved":"https://registry.example.test/cycle-b.tgz","integrity":"sha512-cycle-b","dependencies":{"cycle-a":"1.0.0","z-new":"1.0.0"}},
                "node_modules/z-new": {"version":"1.0.0","resolved":"https://registry.example.test/z-new.tgz","integrity":"sha512-z-new"}
            }
        }"#,
    )
    .unwrap();

    for package in ["cycle-a", "cycle-b", "z-new"] {
        fs::create_dir(packages.path().join(package)).unwrap();
    }
    fs::write(
        packages.path().join("cycle-a/package.json"),
        r#"{"dependencies":{"cycle-b":"1.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        packages.path().join("cycle-b/package.json"),
        r#"{"dependencies":{"cycle-a":"1.0.0","z-new":"1.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        packages.path().join("z-new/package.json"),
        r#"{"name":"z-new","version":"1.0.0"}"#,
    )
    .unwrap();

    (root, packages)
}

fn exact_cycle_limit() -> EngineLimits {
    EngineLimits {
        max_packages: 4,
        ..EngineLimits::default()
    }
}

fn assert_cycle_completed_at_limit(
    report: &crate::model::Report,
    fetches: &Arc<Mutex<HashMap<String, usize>>>,
) {
    assert!(report.issues.is_empty(), "{:?}", report.issues);
    assert_eq!(report.packages.len(), 4);
    assert!(
        report
            .packages
            .iter()
            .any(|package| package.package_id == "npm:z-new@1.0.0#sha512-z-new")
    );

    let fetches = fetches.lock().unwrap();
    for package in ["cycle-a", "cycle-b", "z-new"] {
        assert_eq!(
            fetches.get(&format!("npm:{package}@1.0.0#sha512-{package}")),
            Some(&1),
            "expected {package} to be acquired exactly once"
        );
    }
}
