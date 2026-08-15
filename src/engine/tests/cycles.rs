use super::*;

#[tokio::test]
async fn root_npm_lock_dependency_cycle_terminates_and_analyzes_each_package_once() {
    let root = tempfile::tempdir().unwrap();
    let packages = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"dependencies":{"a":"1.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("package-lock.json"),
        r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies":{"a":"1.0.0"}},
                "node_modules/a": {
                    "version":"1.0.0",
                    "resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz",
                    "integrity":"sha512-a",
                    "dependencies":{"b":"1.0.0"}
                },
                "node_modules/b": {
                    "version":"1.0.0",
                    "resolved":"https://registry.npmjs.org/b/-/b-1.0.0.tgz",
                    "integrity":"sha512-b",
                    "dependencies":{"a":"1.0.0"}
                }
            }
        }"#,
    )
    .unwrap();
    fs::create_dir(packages.path().join("a")).unwrap();
    fs::write(
        packages.path().join("a/package.json"),
        r#"{"dependencies":{"b":"1.0.0"}}"#,
    )
    .unwrap();
    fs::create_dir(packages.path().join("b")).unwrap();
    fs::write(
        packages.path().join("b/package.json"),
        r#"{"dependencies":{"a":"1.0.0"}}"#,
    )
    .unwrap();

    let fetcher = FixtureFetcher {
        packages: packages.path().to_owned(),
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
    assert_eq!(report.packages.len(), 3);
    for package_id in ["root", "npm:a@1.0.0#sha512-a", "npm:b@1.0.0#sha512-b"] {
        assert_eq!(
            report
                .packages
                .iter()
                .filter(|package| package.package_id == package_id)
                .count(),
            1,
            "expected {package_id} to be analyzed exactly once"
        );
    }
}

#[tokio::test]
async fn fetched_root_reached_through_cycle_is_not_analyzed_twice() {
    let packages = tempfile::tempdir().unwrap();
    let webpack = packages.path().join("webpack");
    let cycle_a = packages.path().join("cycle-a");
    fs::create_dir(&webpack).unwrap();
    fs::create_dir(&cycle_a).unwrap();
    fs::write(
        webpack.join("package.json"),
        r#"{"name":"webpack","version":"1.0.0","dependencies":{"cycle-a":"1.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        webpack.join("package-lock.json"),
        r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {"name":"webpack","version":"1.0.0","dependencies":{"cycle-a":"1.0.0"}},
                "node_modules/cycle-a": {"version":"1.0.0","resolved":"https://registry.example.test/cycle-a.tgz","integrity":"sha512-cycle-a","dependencies":{"webpack":"1.0.0"}},
                "node_modules/webpack": {"version":"1.0.0","resolved":"https://registry.example.test/webpack.tgz","integrity":"sha512-webpack"}
            }
        }"#,
    )
    .unwrap();
    fs::write(webpack.join("index.js"), "module.exports = {};\n").unwrap();
    fs::write(
        cycle_a.join("package.json"),
        r#"{"name":"cycle-a","version":"1.0.0","dependencies":{"webpack":"1.0.0"}}"#,
    )
    .unwrap();
    fs::write(cycle_a.join("index.js"), "module.exports = {};\n").unwrap();

    let fetcher = FixtureFetcher {
        packages: packages.path().to_owned(),
    };
    let report = Engine::new(
        &[],
        &fetcher,
        engine_policy(
            EngineLimits {
                max_packages: 2,
                ..EngineLimits::default()
            },
            false,
            true,
            vec![],
            false,
            false,
        ),
    )
    .analyze_fetched_root(FetchMetadata {
        source: webpack,
        package_id: "npm:webpack@1.0.0#sha512-webpack".to_owned(),
        resolved_version: "1.0.0".to_owned(),
        digest: "sha512-webpack".to_owned(),
        source_url: "https://registry.example.test/webpack.tgz".to_owned(),
        cache_hit: false,
    })
    .await
    .unwrap();

    assert!(report.issues.is_empty(), "{:?}", report.issues);
    assert_eq!(report.packages.len(), 2);
    assert_eq!(report.statistics.source_files, 2);
    assert_eq!(
        report
            .packages
            .iter()
            .filter(|package| package.package_id == "npm:webpack@1.0.0#sha512-webpack")
            .count(),
        1,
    );
}
