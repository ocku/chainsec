use super::*;

#[tokio::test]
async fn fetched_roots_fetch_same_dependency_id_from_distinct_source_urls_independently() {
    let packages = tempfile::tempdir().unwrap();
    for package in ["root-denied", "root-allowed", "shared"] {
        fs::create_dir(packages.path().join(package)).unwrap();
    }

    let denied_url = "https://denied.example.test/shared.tgz";
    let allowed_url = "https://allowed.example.test/shared.tgz";
    for (root, source_url) in [("root-denied", denied_url), ("root-allowed", allowed_url)] {
        fs::write(
            packages.path().join(root).join("package.json"),
            r#"{"dependencies":{"shared":"1.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            packages.path().join(root).join("package-lock.json"),
            format!(
                r#"{{
                    "lockfileVersion": 3,
                    "packages": {{
                        "": {{"dependencies":{{"shared":"1.0.0"}}}},
                        "node_modules/shared": {{"version":"1.0.0","resolved":"{source_url}","integrity":"sha512-shared"}}
                    }}
                }}"#
            ),
        )
        .unwrap();
    }
    fs::write(
        packages.path().join("shared/package.json"),
        r#"{"name":"shared","version":"1.0.0"}"#,
    )
    .unwrap();

    let fetches = Arc::new(Mutex::new(Vec::new()));
    let fetcher = SourceUrlPolicyFetcher {
        package: packages.path().join("shared"),
        denied_url: denied_url.to_owned(),
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
            source: packages.path().join("root-denied"),
            package_id: "npm:root-denied@1.0.0#sha512-root-denied".to_owned(),
            resolved_version: "1.0.0".to_owned(),
            digest: "sha512-root-denied".to_owned(),
            source_url: "https://roots.example.test/denied.tgz".to_owned(),
            cache_hit: false,
        },
        FetchMetadata {
            source: packages.path().join("root-allowed"),
            package_id: "npm:root-allowed@1.0.0#sha512-root-allowed".to_owned(),
            resolved_version: "1.0.0".to_owned(),
            digest: "sha512-root-allowed".to_owned(),
            source_url: "https://roots.example.test/allowed.tgz".to_owned(),
            cache_hit: false,
        },
    ])
    .await
    .unwrap();

    let mut fetched_urls = fetches.lock().unwrap().clone();
    fetched_urls.sort();
    assert_eq!(fetched_urls, [allowed_url, denied_url]);
    assert!(
        reports[0]
            .issues
            .iter()
            .any(|issue| issue.code == "policy_error")
    );
    assert_eq!(reports[0].packages.len(), 1);
    assert!(reports[1].issues.is_empty(), "{:?}", reports[1].issues);
    assert_eq!(reports[1].packages.len(), 2);
    assert_eq!(
        reports[1]
            .packages
            .iter()
            .find(|package| package.package_id == "npm:shared@1.0.0#sha512-shared")
            .unwrap()
            .source_url
            .as_deref(),
        Some(allowed_url)
    );
}
