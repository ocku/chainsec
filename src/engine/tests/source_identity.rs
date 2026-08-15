use super::*;

struct StableLocalFetcher;
struct StableAuthenticatedFetcher;

#[async_trait]
impl Fetcher for StableLocalFetcher {
    fn prepare_fetch(
        &self,
        dependency: Dependency,
        declared_from: PathBuf,
    ) -> Result<crate::fetcher::PreparedFetch> {
        prepare_canonical_fixture_fetch(dependency, declared_from)
    }

    async fn fetch(&self, dependency: Dependency, declared_from: PathBuf) -> Result<FetchMetadata> {
        let relative = dependency
            .requirement
            .strip_prefix("file:")
            .expect("test dependencies must be local file dependencies");
        let source = fs::canonicalize(declared_from.join(relative)).unwrap();

        let package_id = dependency.local_source_id(&source);
        Ok(FetchMetadata {
            source,
            package_id,
            resolved_version: "local".to_owned(),
            digest: "local-unverified".to_owned(),
            source_url: dependency.requirement,
            cache_hit: false,
        })
    }
}

#[async_trait]
impl Fetcher for StableAuthenticatedFetcher {
    async fn fetch(&self, dependency: Dependency, declared_from: PathBuf) -> Result<FetchMetadata> {
        let relative = dependency
            .requirement
            .strip_prefix("file:")
            .expect("test dependencies must be local file dependencies");
        let source = fs::canonicalize(declared_from.join(relative)).unwrap();

        Ok(FetchMetadata {
            source,
            package_id: "npm:authenticated@1.0.0#sha512-authenticated".to_owned(),
            resolved_version: "1.0.0".to_owned(),
            digest: "sha512-authenticated".to_owned(),
            source_url: dependency.requirement,
            cache_hit: false,
        })
    }
}

#[tokio::test]
async fn distinct_local_sources_with_the_same_unverified_id_are_both_analyzed() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"dependencies":{"parent-a":"file:./parent-a","parent-b":"file:./parent-b"}}"#,
    )
    .unwrap();

    for (parent, source_file) in [("parent-a", "source-a.js"), ("parent-b", "source-b.js")] {
        let parent = root.path().join(parent);
        let shared = parent.join("shared");
        fs::create_dir_all(&shared).unwrap();
        fs::write(
            parent.join("package.json"),
            r#"{"dependencies":{"shared":"file:./shared"}}"#,
        )
        .unwrap();
        fs::write(
            shared.join("package.json"),
            r#"{"name":"shared","version":"1.0.0"}"#,
        )
        .unwrap();
        fs::write(shared.join(source_file), "eval(payload);\n").unwrap();
    }

    let rules = crate::rules::built_in_rules()
        .into_iter()
        .filter(|rule| rule.id == "chainsec.js.detection.dynamic-code-execution")
        .collect::<Vec<_>>();
    let report = Engine::new(
        &rules,
        &StableLocalFetcher,
        engine_policy(
            EngineLimits {
                max_findings: 1,
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

    assert_eq!(report.issues.len(), 1, "{:?}", report.issues);
    assert_eq!(report.issues[0].package.as_deref(), Some("root"));
    assert_eq!(report.issues[0].code, "limit_exceeded");
    assert_eq!(report.packages.len(), 5);

    let shared_id_prefix = "npm:shared@file:./shared#unverified@local-source:sha256:";
    let shared_packages = report
        .packages
        .iter()
        .filter(|package| package.package_id.starts_with(shared_id_prefix))
        .collect::<Vec<_>>();
    assert_eq!(shared_packages.len(), 2);
    let shared_ids = shared_packages
        .iter()
        .map(|package| package.package_id.clone())
        .collect::<HashSet<_>>();
    assert_eq!(shared_ids.len(), 2);
    assert!(
        shared_packages
            .iter()
            .all(|package| package.scanned_files == 1)
    );
    assert_eq!(
        shared_packages
            .iter()
            .map(|package| package.source.clone())
            .collect::<HashSet<_>>(),
        HashSet::from([
            fs::canonicalize(root.path().join("parent-a/shared")).unwrap(),
            fs::canonicalize(root.path().join("parent-b/shared")).unwrap(),
        ])
    );

    let shared_findings = report
        .findings
        .iter()
        .filter(|finding| finding.package.starts_with(shared_id_prefix))
        .collect::<Vec<_>>();
    assert_eq!(shared_findings.len(), 2);
    assert_eq!(
        shared_findings
            .iter()
            .map(|finding| finding.package.clone())
            .collect::<HashSet<_>>(),
        shared_ids
    );
    assert_eq!(
        shared_findings
            .into_iter()
            .map(|finding| finding.file.clone())
            .collect::<HashSet<_>>(),
        HashSet::from([PathBuf::from("source-a.js"), PathBuf::from("source-b.js")])
    );
}

#[tokio::test]
async fn authenticated_packages_with_the_same_id_still_deduplicate_across_sources() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"dependencies":{"copy-a":"file:./copy-a","copy-b":"file:./copy-b"}}"#,
    )
    .unwrap();
    for package in ["copy-a", "copy-b"] {
        let source = root.path().join(package);
        fs::create_dir(&source).unwrap();
        fs::write(source.join("index.js"), "module.exports = {};\n").unwrap();
    }

    let report = Engine::new(
        &[],
        &StableAuthenticatedFetcher,
        engine_policy(EngineLimits::default(), true, true, vec![], false, false),
    )
    .analyze(root.path())
    .await
    .unwrap();

    assert!(report.issues.is_empty(), "{:?}", report.issues);
    let authenticated_packages = report
        .packages
        .iter()
        .filter(|package| package.package_id == "npm:authenticated@1.0.0#sha512-authenticated")
        .collect::<Vec<_>>();
    assert_eq!(authenticated_packages.len(), 1);
    assert_eq!(authenticated_packages[0].scanned_files, 1);
}

#[tokio::test]
async fn unverified_local_cycle_terminates_when_a_source_is_revisited() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"dependencies":{"a":"file:./a"}}"#,
    )
    .unwrap();
    for (package, dependency) in [
        ("a", r#"{"dependencies":{"b":"file:../b"}}"#),
        ("b", r#"{"dependencies":{"a":"file:../a"}}"#),
    ] {
        let source = root.path().join(package);
        fs::create_dir(&source).unwrap();
        fs::write(source.join("package.json"), dependency).unwrap();
    }

    let report = Engine::new(
        &[],
        &StableLocalFetcher,
        engine_policy(EngineLimits::default(), true, true, vec![], false, false),
    )
    .analyze(root.path())
    .await
    .unwrap();

    assert!(report.issues.is_empty(), "{:?}", report.issues);
    assert_eq!(report.packages.len(), 3);
    assert_eq!(
        report
            .packages
            .iter()
            .map(|package| package.source.clone())
            .collect::<HashSet<_>>(),
        HashSet::from([
            fs::canonicalize(root.path()).unwrap(),
            fs::canonicalize(root.path().join("a")).unwrap(),
            fs::canonicalize(root.path().join("b")).unwrap(),
        ])
    );
}

#[tokio::test]
async fn one_traversal_checks_distinct_urls_for_the_same_authenticated_package() {
    let root = tempfile::tempdir().unwrap();
    let shared = tempfile::tempdir().unwrap();
    let allowed_url = "https://allowed.example.test/shared.tgz";
    let denied_url = "https://denied.example.test/shared.tgz";
    fs::write(
        root.path().join("package.json"),
        r#"{"dependencies":{"shared":"1.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("package-lock.json"),
        format!(
            r#"{{
                "lockfileVersion": 3,
                "packages": {{
                    "": {{"dependencies":{{"shared":"1.0.0"}}}},
                    "node_modules/shared": {{"version":"1.0.0","resolved":"{allowed_url}","integrity":"sha512-shared"}}
                }}
            }}"#
        ),
    )
    .unwrap();
    fs::write(
        shared.path().join("package.json"),
        r#"{"name":"shared","version":"1.0.0","dependencies":{"shared":"1.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        shared.path().join("package-lock.json"),
        format!(
            r#"{{
                "lockfileVersion": 3,
                "packages": {{
                    "": {{"dependencies":{{"shared":"1.0.0"}}}},
                    "node_modules/shared": {{"version":"1.0.0","resolved":"{denied_url}","integrity":"sha512-shared"}}
                }}
            }}"#
        ),
    )
    .unwrap();

    let fetches = Arc::new(Mutex::new(Vec::new()));
    let fetcher = SourceUrlPolicyFetcher {
        package: shared.path().to_owned(),
        denied_url: denied_url.to_owned(),
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

    let mut fetched_urls = fetches.lock().unwrap().clone();
    fetched_urls.sort();
    assert_eq!(fetched_urls, [allowed_url, denied_url]);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| { issue.code == "policy_error" && issue.message.contains(denied_url) })
    );
    assert_eq!(report.packages.len(), 2);
}

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
        engine_policy(EngineLimits::default(), true, true, vec![], false, false),
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
