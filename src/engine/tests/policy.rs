use super::*;

#[tokio::test]
async fn capability_rules_are_reported_separately_from_findings() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("server.py"), "server.listen()\n").unwrap();
    let rules = crate::rules::capability_rules()
        .into_iter()
        .filter(|rule| rule.id == "chainsec.py.capability.network-listen")
        .collect::<Vec<_>>();
    let report = Engine::new(
        &rules,
        &NeverFetch,
        EngineLimits::default(),
        false,
        false,
        vec![],
        false,
    )
    .analyze(root.path())
    .await
    .unwrap();

    assert!(report.findings.is_empty());
    assert_eq!(report.statistics.findings, 0);
    assert_eq!(report.capabilities.len(), 1);
    assert_eq!(report.capabilities[0].name, "network:listen");
    assert_eq!(report.capabilities[0].evidence.len(), 1);
    assert_eq!(
        report.capabilities[0].evidence[0].rule_id,
        "chainsec.py.capability.network-listen"
    );
}

#[tokio::test]
async fn javascript_deno_listeners_are_reported_as_network_listen() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("server.js"),
        "Deno.serve(handler); Deno.serveHttp(conn); Deno.listen({}); Deno.listenTls({}); Deno.connect({}); Deno.connectTls({});\n",
    )
    .unwrap();
    let rules = crate::rules::built_in_rules()
        .into_iter()
        .filter(|rule| {
            matches!(
                rule.id.as_str(),
                "chainsec.js.detection.network-request" | "chainsec.js.detection.network-listen"
            )
        })
        .collect::<Vec<_>>();
    let report = Engine::new(
        &rules,
        &NeverFetch,
        EngineLimits::default(),
        false,
        false,
        vec![],
        false,
    )
    .analyze(root.path())
    .await
    .unwrap();

    assert_eq!(
        report
            .capabilities
            .iter()
            .find(|capability| capability.name == "network:listen")
            .unwrap()
            .evidence
            .len(),
        4
    );
    assert_eq!(
        report
            .capabilities
            .iter()
            .find(|capability| capability.name == "network:connect")
            .unwrap()
            .evidence
            .len(),
        2
    );
}

#[tokio::test]
async fn typescript_deno_listeners_are_reported_as_network_listen() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("server.ts"),
        "Deno.serve(handler); Deno.serveHttp(conn); Deno.listen({}); Deno.listenTls({}); Deno.connect({}); Deno.connectTls({});\n",
    )
    .unwrap();
    let rules = crate::rules::built_in_rules()
        .into_iter()
        .filter(|rule| {
            matches!(
                rule.id.as_str(),
                "chainsec.ts.detection.network-request" | "chainsec.ts.detection.network-listen"
            )
        })
        .collect::<Vec<_>>();
    let report = Engine::new(
        &rules,
        &NeverFetch,
        EngineLimits::default(),
        false,
        false,
        vec![],
        false,
    )
    .analyze(root.path())
    .await
    .unwrap();

    assert_eq!(
        report
            .capabilities
            .iter()
            .find(|capability| capability.name == "network:listen")
            .unwrap()
            .evidence
            .len(),
        4
    );
    assert_eq!(
        report
            .capabilities
            .iter()
            .find(|capability| capability.name == "network:connect")
            .unwrap()
            .evidence
            .len(),
        2
    );
}

#[test]
fn capability_rules_declare_a_capability() {
    let rules = crate::rules::capability_rules();

    assert!(!rules.is_empty());
    for rule in rules {
        assert!(rule.capability.is_some(), "{}", rule.id);
    }
}

#[tokio::test]
async fn unlocked_dependencies_are_policy_issues() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"dependencies":{"left-pad":"^1"}}"#,
    )
    .unwrap();
    let rules = crate::rules::built_in_rules();
    let report = Engine::new(
        &rules,
        &NeverFetch,
        EngineLimits::default(),
        true,
        true,
        vec![],
        false,
    )
    .analyze(root.path())
    .await
    .unwrap();
    assert_eq!(report.packages.len(), 1);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == "policy_error")
    );
}

#[tokio::test]
async fn fetched_packages_scan_vendored_node_modules() {
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/scanner/vendored-node-modules");
    let rules = crate::rules::built_in_rules();
    let report = Engine::new(
        &rules,
        &NeverFetch,
        EngineLimits::default(),
        true,
        true,
        vec![],
        false,
    )
    .analyze_fetched_root(FetchMetadata {
        source,
        package_id: "npm:vendored@1.0.0#sha512-vendored".to_owned(),
        resolved_version: "1.0.0".to_owned(),
        digest: "sha512-vendored".to_owned(),
        source_url: "https://registry.example.test/vendored.tgz".to_owned(),
        cache_hit: false,
    })
    .await
    .unwrap();

    assert!(report.findings.iter().any(|finding| {
        finding.file == std::path::Path::new("node_modules/evil/index.js")
            && finding.rule_id == "chainsec.js.detection.dynamic-code-execution"
            && finding.package == "npm:vendored@1.0.0#sha512-vendored"
    }));
}

#[tokio::test]
async fn fetched_root_bypasses_lockfile_policy_but_dependencies_do_not() {
    let source = tempfile::tempdir().unwrap();
    fs::write(
        source.path().join("package.json"),
        r#"{"dependencies":{"left-pad":"^1"},"scripts":{"postinstall":"node setup.js"}}"#,
    )
    .unwrap();
    fs::write(source.path().join("index.js"), "eval(payload);").unwrap();
    let rules = crate::rules::built_in_rules();
    let report = Engine::new(
        &rules,
        &NeverFetch,
        EngineLimits::default(),
        true,
        true,
        vec![],
        false,
    )
    .analyze_fetched_root(FetchMetadata {
        source: source.path().to_owned(),
        package_id: "npm:remote@1.0.0#sha512-remote".to_owned(),
        resolved_version: "1.0.0".to_owned(),
        digest: "sha512-remote".to_owned(),
        source_url: "https://registry.example.test/remote-1.0.0.tgz".to_owned(),
        cache_hit: false,
    })
    .await
    .unwrap();

    let remote_package_id = "npm:remote@1.0.0#sha512-remote";
    assert_eq!(report.packages[0].package_id, remote_package_id);
    assert_eq!(
        report.packages[0].source_url.as_deref(),
        Some("https://registry.example.test/remote-1.0.0.tgz")
    );
    assert!(report.findings.iter().any(|finding| {
        finding.finding_type == crate::model::FindingType::InstallScript
            && finding.package == remote_package_id
    }));
    assert!(report.findings.iter().any(|finding| {
        finding.rule_id == "chainsec.js.detection.dynamic-code-execution"
            && finding.package == remote_package_id
    }));
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.package == remote_package_id)
    );
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == "policy_error")
    );
}
