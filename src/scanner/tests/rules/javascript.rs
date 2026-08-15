use std::fs;

use super::super::super::*;
use crate::rules::default_rules as built_in_rules;

#[test]
fn js010_only_reports_assignments_to_window() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("window.js"),
        concat!(
            "window.location = url;\n",
            "window['name'] = value;\n",
            "result.length = len;\n",
            "exports.value = value;\n",
            "globalThis.value = value;\n",
        ),
    )
    .unwrap();

    let outcome = scan(
        directory.path(),
        "root",
        &built_in_rules(),
        &EngineLimits::default(),
    )
    .unwrap();
    let findings = outcome
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "chainsec.js.detection.write-browser-global")
        .collect::<Vec<_>>();

    assert_eq!(findings.len(), 2);
    assert!(
        findings
            .iter()
            .any(|finding| finding.matched_code.contains("window.location"))
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.matched_code.contains("window['name']"))
    );
}

#[test]
fn dynamic_execution_query_uses_syntax_not_line_heuristics() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("contexts.ts"),
        concat!(
            "// eval(payload)\n",
            "const example = 'eval(payload)';\n",
            "interface Evaluator { eval(payload: string): unknown; }\n",
            "type EvaluatorAlias = { eval(payload: string): unknown };\n",
            "const label = 'trusted'; eval(payload);\n",
        ),
    )
    .unwrap();

    let outcome = scan(
        directory.path(),
        "root",
        &built_in_rules(),
        &EngineLimits::default(),
    )
    .unwrap();
    let findings = outcome
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "chainsec.ts.detection.dynamic-code-execution")
        .collect::<Vec<_>>();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].location.start_line, 5);
}

#[test]
fn numeric_require_is_not_reported_as_dynamic_loading() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("bundle.js"),
        "require(23);\nrequire(moduleName);\n",
    )
    .unwrap();

    let outcome = scan(
        directory.path(),
        "root",
        &built_in_rules(),
        &EngineLimits::default(),
    )
    .unwrap();
    let findings = outcome
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "chainsec.js.detection.dynamic-require")
        .collect::<Vec<_>>();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].location.start_line, 2);
}

#[test]
fn static_template_literal_module_specifiers_are_not_reported_as_dynamic_loading() {
    let directory = tempfile::tempdir().unwrap();
    let source = concat!(
        "require(`./safe.js`);\n",
        "import(`./safe.js`);\n",
        "require(`./${moduleName}.js`);\n",
        "import(`./${moduleName}.js`);\n",
    );
    fs::write(directory.path().join("module.js"), source).unwrap();
    fs::write(directory.path().join("module.ts"), source).unwrap();

    let outcome = scan(
        directory.path(),
        "root",
        &built_in_rules(),
        &EngineLimits::default(),
    )
    .unwrap();

    for language in ["js", "ts"] {
        for loader in ["require", "import"] {
            let rule_id = format!("chainsec.{language}.detection.dynamic-{loader}");
            let findings = outcome
                .findings
                .iter()
                .filter(|finding| finding.rule_id == rule_id)
                .collect::<Vec<_>>();

            assert_eq!(
                findings.len(),
                1,
                "expected one dynamic {loader} finding for {language}"
            );
            let expected_line = if loader == "require" { 3 } else { 4 };
            assert_eq!(findings[0].location.start_line, expected_line);
        }
    }
}

#[test]
fn function_constructor_reports_short_static_payloads() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("constructors.js"),
        concat!(
            "Function('return 1');\n",
            "Function(\"require('child_process')\")();\n",
            "Function('12345678901234567890123456789012');\n",
            "Function('123456789012345678901234567890123');\n",
            "Function(source);\n",
            "Function('value', 'return ' + value);\n",
        ),
    )
    .unwrap();

    let outcome = scan(
        directory.path(),
        "root",
        &built_in_rules(),
        &EngineLimits::default(),
    )
    .unwrap();
    let mut matched_code = outcome
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "chainsec.js.detection.dynamic-code-execution")
        .map(|finding| finding.matched_code.as_str())
        .collect::<Vec<_>>();
    matched_code.sort_unstable();

    assert_eq!(
        matched_code,
        vec![
            "Function(\"require('child_process')\")",
            "Function('12345678901234567890123456789012')",
            "Function('123456789012345678901234567890123')",
            "Function('return 1')",
            "Function('value', 'return ' + value)",
            "Function(source)",
        ]
    );
}

#[test]
fn dynamic_execution_query_does_not_guess_alias_bindings() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("aliases.js"),
        concat!(
            "const run = eval;\n",
            "api.run(payload);\n",
            "function safe(run) { run(payload); }\n",
            "let reassigned = eval;\n",
            "reassigned = harmless;\n",
            "reassigned(payload);\n",
        ),
    )
    .unwrap();

    let outcome = scan(
        directory.path(),
        "root",
        &built_in_rules(),
        &EngineLimits::default(),
    )
    .unwrap();
    assert!(
        !outcome
            .findings
            .iter()
            .any(|finding| finding.rule_id == "chainsec.js.detection.dynamic-code-execution")
    );
}

#[test]
fn dynamic_execution_query_reports_direct_named_calls() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("scopes.js"),
        concat!(
            "function wrapper(eval) { return eval(payload); }\n",
            "const Function = safe; Function(payload);\n",
            "const value = 1; eval(payload);\n",
        ),
    )
    .unwrap();

    let outcome = scan(
        directory.path(),
        "root",
        &built_in_rules(),
        &EngineLimits::default(),
    )
    .unwrap();
    let findings = outcome
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "chainsec.js.detection.dynamic-code-execution")
        .collect::<Vec<_>>();

    assert_eq!(findings.len(), 3);
    let mut matched_code = findings
        .iter()
        .map(|finding| finding.matched_code.as_str())
        .collect::<Vec<_>>();
    matched_code.sort_unstable();
    assert_eq!(
        matched_code,
        vec!["Function(payload)", "eval(payload)", "eval(payload)"]
    );
}

#[test]
fn scanner_ignores_character_formatting_as_obfuscation() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("format.js"),
        concat!(
            "const normalized = [...colorString].map(character => character + character).join('');\n",
            "const booleanOpts = [].concat(opts.boolean).filter(Boolean);\n",
            "const aliases = [name].concat(aliasList).join('|');\n",
            "const formatted = String.fromCharCode(parseInt(arg, 10))\n",
            "const decoded = String.fromCharCode(72, 101, 108, 108, 111)\n",
            "const hidden = [104, 116, 116, 112, 115, 58, 47, 47].map(c => String.fromCharCode(c)).join('');\n",
        ),
    )
    .unwrap();

    let outcome = scan(
        directory.path(),
        "root",
        &built_in_rules(),
        &EngineLimits::default(),
    )
    .unwrap();
    let decoded_findings = outcome
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "chainsec.js.detection.decoded-payload")
        .collect::<Vec<_>>();
    let assembly_findings = outcome
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "chainsec.js.detection.character-code-assembly")
        .collect::<Vec<_>>();

    assert_eq!(decoded_findings.len(), 1);
    assert!(decoded_findings[0].matched_code.contains("72, 101"));
    assert_eq!(assembly_findings.len(), 1);
    assert!(assembly_findings[0].matched_code.contains("104, 116"));
}
