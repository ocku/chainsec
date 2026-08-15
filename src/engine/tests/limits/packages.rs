use super::super::*;

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
    let reports = Engine::new(
        &[],
        &fetcher,
        engine_policy(limits, true, true, vec![], false, false),
    )
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
async fn single_root_same_acquisition_with_different_ranges_counts_once() {
    let root = tempfile::tempdir().unwrap();
    let packages = tempfile::tempdir().unwrap();
    for package in [
        "parent-a",
        "parent-b",
        "shared",
        "child-1.0.0",
        "child-2.0.0",
    ] {
        fs::create_dir(packages.path().join(package)).unwrap();
    }

    fs::write(
        root.path().join("package.json"),
        r#"{"dependencies":{"parent-a":"1.0.0","parent-b":"1.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("package-lock.json"),
        r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies":{"parent-a":"1.0.0","parent-b":"1.0.0"}},
                "node_modules/parent-a": {"version":"1.0.0","resolved":"https://registry.example.test/parent-a.tgz","integrity":"sha512-parent-a","dependencies":{"shared":"^1.0.0"}},
                "node_modules/parent-b": {"version":"1.0.0","resolved":"https://registry.example.test/parent-b.tgz","integrity":"sha512-parent-b","dependencies":{"shared":"~1.0.0"}},
                "node_modules/parent-a/node_modules/shared": {"version":"1.0.0","resolved":"https://registry.example.test/shared.tgz","integrity":"sha512-shared","dependencies":{"child":"*"}},
                "node_modules/parent-b/node_modules/shared": {"version":"1.0.0","resolved":"https://registry.example.test/shared.tgz","integrity":"sha512-shared","dependencies":{"child":"*"}},
                "node_modules/parent-a/node_modules/shared/node_modules/child": {"version":"1.0.0","resolved":"https://registry.example.test/child-1.tgz","integrity":"sha512-child-1"},
                "node_modules/parent-b/node_modules/shared/node_modules/child": {"version":"2.0.0","resolved":"https://registry.example.test/child-2.tgz","integrity":"sha512-child-2"}
            }
        }"#,
    )
    .unwrap();
    for (parent, requirement) in [("parent-a", "^1.0.0"), ("parent-b", "~1.0.0")] {
        fs::write(
            packages.path().join(parent).join("package.json"),
            format!(r#"{{"dependencies":{{"shared":"{requirement}"}}}}"#),
        )
        .unwrap();
    }
    fs::write(
        packages.path().join("shared/package.json"),
        r#"{"dependencies":{"child":"*"}}"#,
    )
    .unwrap();
    for version in ["1.0.0", "2.0.0"] {
        fs::write(
            packages
                .path()
                .join(format!("child-{version}/package.json")),
            format!(r#"{{"name":"child","version":"{version}"}}"#),
        )
        .unwrap();
    }

    let fetches = Arc::new(Mutex::new(HashMap::new()));
    let fetcher = ContextFixtureFetcher {
        packages: packages.path().to_owned(),
        fetches: Arc::clone(&fetches),
    };
    let report = Engine::new(
        &[],
        &fetcher,
        engine_policy(
            EngineLimits {
                max_packages: 6,
                ..EngineLimits::default()
            },
            true,
            true,
            vec![],
            false,
            false,
        ),
    )
    .analyze(root.path())
    .await
    .unwrap();

    assert!(report.issues.is_empty(), "{:?}", report.issues);
    assert_eq!(report.packages.len(), 6);
    assert_eq!(
        fetches
            .lock()
            .unwrap()
            .get("npm:shared@1.0.0#sha512-shared"),
        Some(&1)
    );
    for child in [
        "npm:child@1.0.0#sha512-child-1",
        "npm:child@2.0.0#sha512-child-2",
    ] {
        assert!(
            report
                .packages
                .iter()
                .any(|package| package.package_id == child),
            "expected merged discovery contexts to retain {child}"
        );
    }
}

#[tokio::test]
async fn fetched_root_batch_same_acquisition_with_different_ranges_counts_once() {
    let packages = tempfile::tempdir().unwrap();
    for package in ["root", "parent-a", "parent-b", "shared", "zzz"] {
        fs::create_dir(packages.path().join(package)).unwrap();
    }
    fs::write(
        packages.path().join("root/package.json"),
        r#"{"dependencies":{"parent-a":"1.0.0","parent-b":"1.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        packages.path().join("root/package-lock.json"),
        r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies":{"parent-a":"1.0.0","parent-b":"1.0.0"}},
                "node_modules/parent-a": {"version":"1.0.0","resolved":"https://registry.example.test/parent-a.tgz","integrity":"sha512-parent-a","dependencies":{"shared":"^1.0.0"}},
                "node_modules/parent-b": {"version":"1.0.0","resolved":"https://registry.example.test/parent-b.tgz","integrity":"sha512-parent-b","dependencies":{"shared":"~1.0.0","zzz":"1.0.0"}},
                "node_modules/parent-a/node_modules/shared": {"version":"1.0.0","resolved":"https://registry.example.test/shared.tgz","integrity":"sha512-shared"},
                "node_modules/parent-b/node_modules/shared": {"version":"1.0.0","resolved":"https://registry.example.test/shared.tgz","integrity":"sha512-shared"},
                "node_modules/parent-b/node_modules/zzz": {"version":"1.0.0","resolved":"https://registry.example.test/zzz.tgz","integrity":"sha512-zzz"}
            }
        }"#,
    )
    .unwrap();
    for (parent, dependencies) in [
        ("parent-a", r#""shared":"^1.0.0""#),
        ("parent-b", r#""shared":"~1.0.0","zzz":"1.0.0""#),
    ] {
        fs::write(
            packages.path().join(parent).join("package.json"),
            format!(r#"{{"dependencies":{{{dependencies}}}}}"#),
        )
        .unwrap();
    }
    for package in ["shared", "zzz"] {
        fs::write(
            packages.path().join(package).join("package.json"),
            format!(r#"{{"name":"{package}","version":"1.0.0"}}"#),
        )
        .unwrap();
    }

    let fetches = Arc::new(Mutex::new(HashMap::new()));
    let fetcher = CountingFixtureFetcher {
        packages: packages.path().to_owned(),
        fetches: Arc::clone(&fetches),
    };
    let reports = Engine::new(
        &[],
        &fetcher,
        engine_policy(
            EngineLimits {
                max_packages: 5,
                ..EngineLimits::default()
            },
            true,
            true,
            vec![],
            false,
            false,
        ),
    )
    .analyze_fetched_roots(vec![fetched_fixture_root(
        packages.path().join("root"),
        "npm:root@1.0.0#sha512-root",
    )])
    .await
    .unwrap();

    assert_eq!(
        fetches
            .lock()
            .unwrap()
            .get("npm:shared@1.0.0#sha512-shared"),
        Some(&1)
    );
    assert_eq!(
        fetches.lock().unwrap().get("npm:zzz@1.0.0#sha512-zzz"),
        Some(&1)
    );
    assert_eq!(reports.len(), 1);
    assert!(reports[0].issues.is_empty(), "{:?}", reports[0].issues);
    assert_eq!(reports[0].packages.len(), 5);
}

#[tokio::test]
async fn single_root_fetch_attempts_are_bounded_when_a_dependency_fetch_fails() {
    let root = tempfile::tempdir().unwrap();
    let packages = tempfile::tempdir().unwrap();
    for package in ["successful", "child"] {
        fs::create_dir(packages.path().join(package)).unwrap();
    }
    fs::write(
        root.path().join("package.json"),
        r#"{"dependencies":{"successful":"1.0.0","missing":"1.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("package-lock.json"),
        r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies":{"successful":"1.0.0","missing":"1.0.0"}},
                "node_modules/successful": {"version":"1.0.0","resolved":"https://registry.example.test/successful.tgz","integrity":"sha512-successful"},
                "node_modules/missing": {"version":"1.0.0","resolved":"https://registry.example.test/missing.tgz","integrity":"sha512-missing"}
            }
        }"#,
    )
    .unwrap();
    fs::write(
        packages.path().join("successful/package.json"),
        r#"{"dependencies":{"child":"1.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        packages.path().join("successful/package-lock.json"),
        r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies":{"child":"1.0.0"}},
                "node_modules/child": {"version":"1.0.0","resolved":"https://registry.example.test/child.tgz","integrity":"sha512-child"}
            }
        }"#,
    )
    .unwrap();
    fs::write(
        packages.path().join("child/package.json"),
        r#"{"name":"child","version":"1.0.0"}"#,
    )
    .unwrap();

    let fetches = Arc::new(Mutex::new(HashMap::new()));
    let fetcher = FailingFixtureFetcher {
        packages: packages.path().to_owned(),
        failures: ["missing".to_owned()].into_iter().collect(),
        fetches: Arc::clone(&fetches),
    };
    let report = Engine::new(
        &[],
        &fetcher,
        engine_policy(
            EngineLimits {
                max_packages: 3,
                ..EngineLimits::default()
            },
            true,
            true,
            vec![],
            false,
            false,
        ),
    )
    .analyze(root.path())
    .await
    .unwrap();

    assert_eq!(fetches.lock().unwrap().len(), 2);
    assert!(report.issues.iter().any(|issue| {
        issue.fatal && issue.operation == "traversal" && issue.message.contains("packages")
    }));
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
    let reports = Engine::new(
        &[],
        &fetcher,
        engine_policy(limits, true, true, vec![], false, false),
    )
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
