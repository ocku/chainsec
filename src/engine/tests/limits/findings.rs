use super::super::*;

#[tokio::test]
async fn install_hooks_do_not_lose_slots_to_finalized_capabilities() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"scripts":{"postinstall":"node setup.js"}}"#,
    )
    .unwrap();
    fs::write(root.path().join("index.js"), "eval(payload);\n").unwrap();

    let rules = dynamic_execution_detection_and_capability_rules();
    let report = Engine::new(
        &rules,
        &NeverFetch,
        EngineLimits {
            max_findings: 2,
            ..EngineLimits::default()
        },
        false,
        false,
        vec![],
        false,
        false,
    )
    .analyze(root.path())
    .await
    .unwrap();

    assert_install_hook_and_source_finding_fill_budget(&report);
}

#[tokio::test]
async fn batch_install_hooks_do_not_lose_slots_to_finalized_capabilities() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"scripts":{"postinstall":"node setup.js"}}"#,
    )
    .unwrap();
    fs::write(root.path().join("index.js"), "eval(payload);\n").unwrap();

    let rules = dynamic_execution_detection_and_capability_rules();
    let reports = Engine::new(
        &rules,
        &NeverFetch,
        EngineLimits {
            max_findings: 2,
            ..EngineLimits::default()
        },
        false,
        false,
        vec![],
        false,
        false,
    )
    .analyze_fetched_roots(vec![fetched_fixture_root(
        root.path().to_owned(),
        "npm:hooked@1.0.0#sha512-hooked",
    )])
    .await
    .unwrap();

    assert_eq!(reports.len(), 1);
    assert_install_hook_and_source_finding_fill_budget(&reports[0]);
}

#[tokio::test]
async fn critical_source_finding_takes_priority_over_install_hook_at_limit() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"scripts":{"postinstall":"node setup.js"}}"#,
    )
    .unwrap();
    fs::write(root.path().join("index.js"), "danger();\n").unwrap();

    let rules = vec![matching_javascript_rule(
        "review.critical-call",
        crate::model::FindingType::ArbitraryCodeExecution,
        crate::model::Risk::Critical,
    )];
    let report = Engine::new(
        &rules,
        &NeverFetch,
        EngineLimits {
            max_findings: 1,
            ..EngineLimits::default()
        },
        false,
        false,
        vec![],
        false,
        false,
    )
    .analyze(root.path())
    .await
    .unwrap();

    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].rule_id, "review.critical-call");
    assert_eq!(report.findings[0].risk, crate::model::Risk::Critical);
    assert!(report.issues.iter().any(|issue| {
        issue.code == "limit_exceeded" && issue.operation == "report finalization"
    }));
}

#[tokio::test]
async fn finding_limit_preserves_the_bounded_partial_scan() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("index.js"), "danger();\n").unwrap();

    let rules = vec![
        matching_javascript_rule(
            "review.low-call",
            crate::model::FindingType::ProcessExecution,
            crate::model::Risk::Low,
        ),
        matching_javascript_rule(
            "review.critical-call",
            crate::model::FindingType::ArbitraryCodeExecution,
            crate::model::Risk::Critical,
        ),
    ];
    let report = Engine::new(
        &rules,
        &NeverFetch,
        EngineLimits {
            max_findings: 1,
            ..EngineLimits::default()
        },
        false,
        false,
        vec![],
        false,
        false,
    )
    .analyze(root.path())
    .await
    .unwrap();

    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].rule_id, "review.critical-call");
    assert_eq!(report.statistics.source_files, 1);
    assert!(
        report.issues.iter().any(|issue| {
            issue.code == "limit_exceeded" && issue.operation == "source scanning"
        })
    );
}

fn matching_javascript_rule(
    id: &str,
    finding_type: crate::model::FindingType,
    risk: crate::model::Risk,
) -> crate::model::Rule {
    crate::model::Rule {
        id: id.to_owned(),
        version: 1,
        language: crate::model::Language::JavaScript,
        finding_type,
        risk,
        confidence: crate::model::Confidence::High,
        rationale: "test finding".to_owned(),
        remediation: "remove it".to_owned(),
        capability: None,
        query: "(call_expression) @match".to_owned(),
        entropy: None,
    }
}

fn dynamic_execution_detection_and_capability_rules() -> Vec<crate::model::Rule> {
    crate::rules::default_rules()
        .into_iter()
        .filter(|rule| {
            matches!(
                rule.id.as_str(),
                "chainsec.js.detection.dynamic-code-execution"
                    | "chainsec.js.capability.dynamic-code-execution"
            )
        })
        .collect()
}

fn assert_install_hook_and_source_finding_fill_budget(report: &crate::model::Report) {
    assert_eq!(report.findings.len(), 2);
    assert_eq!(report.statistics.findings, 2);
    assert!(report.findings.iter().any(|finding| {
        finding.finding_type == crate::model::FindingType::InstallScript
            && finding.rule_id == "chainsec.js.detection.manifest.install-hook"
    }));
    assert!(
        report
            .findings
            .iter()
            .any(|finding| { finding.rule_id == "chainsec.js.detection.dynamic-code-execution" })
    );
    assert_eq!(report.capabilities.len(), 1);
    assert_eq!(report.capabilities[0].name, "code:dynamic-execution");
    assert_eq!(report.capabilities[0].evidence.len(), 1);
}
