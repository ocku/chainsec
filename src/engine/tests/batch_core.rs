use super::*;

#[tokio::test]
async fn fetched_roots_compile_rules_before_fetching_dependencies() {
    let packages = tempfile::tempdir().unwrap();
    fs::create_dir(packages.path().join("root")).unwrap();
    fs::write(
        packages.path().join("root/package.json"),
        r#"{"dependencies":{"shared":"1.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        packages.path().join("root/package-lock.json"),
        r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies":{"shared":"1.0.0"}},
                "node_modules/shared": {"version":"1.0.0","resolved":"https://registry.example.test/shared.tgz","integrity":"sha512-shared"}
            }
        }"#,
    )
    .unwrap();

    let fetches = Arc::new(Mutex::new(HashMap::new()));
    let fetcher = CountingFixtureFetcher {
        packages: packages.path().to_owned(),
        fetches: Arc::clone(&fetches),
    };
    let mut rule = crate::rules::built_in_rules().into_iter().next().unwrap();
    rule.query = "(".to_owned();
    let rules = vec![rule];
    crate::rules::validate_rules(&rules).unwrap();

    let result = Engine::new(
        &rules,
        &fetcher,
        EngineLimits::default(),
        true,
        true,
        vec![],
        false,
    )
    .analyze_fetched_roots(vec![FetchMetadata {
        source: packages.path().join("root"),
        package_id: "npm:root@1.0.0#sha512-root".to_owned(),
        resolved_version: "1.0.0".to_owned(),
        digest: "sha512-root".to_owned(),
        source_url: "https://registry.example.test/root.tgz".to_owned(),
        cache_hit: false,
    }])
    .await;

    assert!(matches!(result, Err(crate::error::Error::Scan { .. })));
    assert!(
        fetches.lock().unwrap().is_empty(),
        "malformed queries must fail before dependency fetching"
    );
}

#[tokio::test]
async fn fetched_roots_share_dependency_acquisition_and_scanning() {
    let packages = tempfile::tempdir().unwrap();
    for package in ["root-a", "root-b", "shared", "only-a", "only-b"] {
        fs::create_dir(packages.path().join(package)).unwrap();
    }
    fs::write(
        packages.path().join("root-a/package.json"),
        r#"{"dependencies":{"shared":"1.0.0","only-a":"1.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        packages.path().join("root-a/package-lock.json"),
        r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies":{"shared":"1.0.0","only-a":"1.0.0"}},
                "node_modules/shared": {"version":"1.0.0","resolved":"https://registry.example.test/shared.tgz","integrity":"sha512-shared"},
                "node_modules/only-a": {"version":"1.0.0","resolved":"https://registry.example.test/only-a.tgz","integrity":"sha512-only-a"}
            }
        }"#,
    )
    .unwrap();
    fs::write(
        packages.path().join("root-b/package.json"),
        r#"{"dependencies":{"shared":"1.0.0","only-b":"1.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        packages.path().join("root-b/package-lock.json"),
        r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies":{"shared":"1.0.0","only-b":"1.0.0"}},
                "node_modules/shared": {"version":"1.0.0","resolved":"https://registry.example.test/shared.tgz","integrity":"sha512-shared"},
                "node_modules/only-b": {"version":"1.0.0","resolved":"https://registry.example.test/only-b.tgz","integrity":"sha512-only-b"}
            }
        }"#,
    )
    .unwrap();
    fs::write(
        packages.path().join("shared/package.json"),
        r#"{"name":"shared","version":"1.0.0"}"#,
    )
    .unwrap();
    fs::write(packages.path().join("shared/index.js"), "eval(payload);\n").unwrap();
    for package in ["only-a", "only-b"] {
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
    let rules = crate::rules::built_in_rules();
    let reports = Engine::new(
        &rules,
        &fetcher,
        EngineLimits::default(),
        true,
        true,
        vec![],
        false,
    )
    .analyze_fetched_roots(vec![
        FetchMetadata {
            source: packages.path().join("root-a"),
            package_id: "npm:example@1.0.0#sha512-root-a".to_owned(),
            resolved_version: "1.0.0".to_owned(),
            digest: "sha512-root-a".to_owned(),
            source_url: "https://registry.example.test/example-1.0.0.tgz".to_owned(),
            cache_hit: false,
        },
        FetchMetadata {
            source: packages.path().join("root-b"),
            package_id: "npm:example@2.0.0#sha512-root-b".to_owned(),
            resolved_version: "2.0.0".to_owned(),
            digest: "sha512-root-b".to_owned(),
            source_url: "https://registry.example.test/example-2.0.0.tgz".to_owned(),
            cache_hit: false,
        },
    ])
    .await
    .unwrap();

    assert_eq!(reports.len(), 2);
    assert_eq!(
        fetches
            .lock()
            .unwrap()
            .get("npm:shared@1.0.0#sha512-shared"),
        Some(&1),
        "shared dependency should be fetched once across roots"
    );
    for report in &reports {
        assert_eq!(report.packages.len(), 3);
        assert!(report.issues.is_empty(), "{:?}", report.issues);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.package == "npm:shared@1.0.0#sha512-shared")
        );
    }
    assert!(
        reports[0]
            .packages
            .iter()
            .any(|package| package.package_id.starts_with("npm:only-a@"))
    );
    assert!(
        !reports[0]
            .packages
            .iter()
            .any(|package| package.package_id.starts_with("npm:only-b@"))
    );
    assert!(
        reports[1]
            .packages
            .iter()
            .any(|package| package.package_id.starts_with("npm:only-b@"))
    );
    assert!(
        !reports[1]
            .packages
            .iter()
            .any(|package| package.package_id.starts_with("npm:only-a@"))
    );
}
