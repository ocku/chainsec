use super::*;

#[tokio::test]
async fn fetched_roots_fetch_distinct_unlocked_deno_npm_requirements_independently() {
    let packages = tempfile::tempdir().unwrap();
    for package in ["root-a", "root-b", "package-a", "package-b"] {
        fs::create_dir(packages.path().join(package)).unwrap();
    }

    for (root, package) in [("root-a", "package-a"), ("root-b", "package-b")] {
        let requirement = format!("npm:{package}@1.0.0");
        fs::write(
            packages.path().join(root).join("deno.json"),
            format!(r#"{{"imports":{{"shared":"{requirement}"}}}}"#),
        )
        .unwrap();
        fs::write(
            packages.path().join(root).join("deno.lock"),
            format!(r#"{{"version":"4","specifiers":{{"{requirement}":"1.0.0"}},"npm":{{}}}}"#),
        )
        .unwrap();
        fs::write(
            packages.path().join(package).join("package.json"),
            format!(r#"{{"name":"{package}","version":"1.0.0"}}"#),
        )
        .unwrap();
    }

    let fetches = Arc::new(Mutex::new(Vec::new()));
    let fetcher = DenoNpmRequirementFetcher {
        packages: packages.path().to_owned(),
        fetches: Arc::clone(&fetches),
    };
    let reports = Engine::new(
        &[],
        &fetcher,
        EngineLimits::default(),
        false,
        false,
        vec![],
        false,
    )
    .analyze_fetched_roots(vec![
        FetchMetadata {
            source: packages.path().join("root-a"),
            package_id: "deno:root-a@1.0.0#sha256-root-a".to_owned(),
            resolved_version: "1.0.0".to_owned(),
            digest: "sha256-root-a".to_owned(),
            source_url: "https://roots.example.test/root-a.tgz".to_owned(),
            cache_hit: false,
        },
        FetchMetadata {
            source: packages.path().join("root-b"),
            package_id: "deno:root-b@1.0.0#sha256-root-b".to_owned(),
            resolved_version: "1.0.0".to_owned(),
            digest: "sha256-root-b".to_owned(),
            source_url: "https://roots.example.test/root-b.tgz".to_owned(),
            cache_hit: false,
        },
    ])
    .await
    .unwrap();

    let mut fetched_requirements = fetches.lock().unwrap().clone();
    fetched_requirements.sort();
    assert_eq!(
        fetched_requirements,
        ["npm:package-a@1.0.0", "npm:package-b@1.0.0"]
    );
    for (index, package) in ["package-a", "package-b"].into_iter().enumerate() {
        assert!(
            reports[index].issues.is_empty(),
            "{:?}",
            reports[index].issues
        );
        assert_eq!(reports[index].packages.len(), 2);
        assert!(reports[index].packages.iter().any(|report_package| {
            report_package.package_id == format!("npm:{package}@1.0.0#sha512-{package}")
                && report_package.source_url.as_deref()
                    == Some(format!("https://registry.example.test/{package}.tgz").as_str())
        }));
    }
}

#[tokio::test]
async fn fetched_roots_verify_shared_deno_graphs_against_each_lockfile() {
    let packages = tempfile::tempdir().unwrap();
    for root in ["root-allowed", "root-denied", "shared"] {
        fs::create_dir(packages.path().join(root)).unwrap();
    }
    let root_url = "https://example.test/shared.ts";
    for (root, decision) in [("root-allowed", "allow"), ("root-denied", "deny")] {
        fs::write(
            packages.path().join(root).join("deno.json"),
            format!(r#"{{"imports":{{"shared":"{root_url}"}}}}"#),
        )
        .unwrap();
        fs::write(
            packages.path().join(root).join("deno.lock"),
            format!(
                r#"{{"version":"4","remote":{{"{root_url}":"sha256:shared"}},"decision":"{decision}"}}"#
            ),
        )
        .unwrap();
    }
    fs::write(packages.path().join("shared/shared.ts"), "export {};").unwrap();

    let fetches = Arc::new(Mutex::new(Vec::new()));
    let fetcher = DenoLockfilePolicyFetcher {
        package: packages.path().join("shared"),
        fetches: Arc::clone(&fetches),
    };
    let reports = Engine::new(
        &[],
        &fetcher,
        EngineLimits::default(),
        true,
        true,
        vec![],
        false,
    )
    .analyze_fetched_roots(vec![
        FetchMetadata {
            source: packages.path().join("root-allowed"),
            package_id: "deno:root@1.0.0#sha256-root-allowed".to_owned(),
            resolved_version: "1.0.0".to_owned(),
            digest: "sha256-root-allowed".to_owned(),
            source_url: "https://roots.example.test/allowed.tgz".to_owned(),
            cache_hit: false,
        },
        FetchMetadata {
            source: packages.path().join("root-denied"),
            package_id: "deno:root@2.0.0#sha256-root-denied".to_owned(),
            resolved_version: "2.0.0".to_owned(),
            digest: "sha256-root-denied".to_owned(),
            source_url: "https://roots.example.test/denied.tgz".to_owned(),
            cache_hit: false,
        },
    ])
    .await
    .unwrap();

    assert_eq!(fetches.lock().unwrap().len(), 2);
    assert!(reports[0].issues.is_empty(), "{:?}", reports[0].issues);
    assert_eq!(reports[0].packages.len(), 2);
    assert!(
        reports[1]
            .issues
            .iter()
            .any(|issue| issue.code == "policy_error")
    );
    assert_eq!(reports[1].packages.len(), 1);
}
