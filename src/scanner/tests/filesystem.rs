use std::fs;

use super::super::*;
use crate::rules::default_rules as built_in_rules;

#[test]
fn local_scans_exclude_node_modules() {
    let directory = tempfile::tempdir().unwrap();
    let vendored_module = directory.path().join("node_modules/evil");
    fs::create_dir_all(&vendored_module).unwrap();
    fs::write(vendored_module.join("index.js"), "eval(payload);\n").unwrap();

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
            .any(|finding| finding.file == Path::new("node_modules/evil/index.js"))
    );
}

#[test]
fn single_file_scan_uses_the_file_name_in_findings() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("payload.js");
    fs::write(&file, "eval(input);\n").unwrap();

    let outcome = scan(&file, "root", &built_in_rules(), &EngineLimits::default()).unwrap();

    assert!(
        outcome
            .findings
            .iter()
            .all(|finding| finding.file == Path::new("payload.js"))
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
fn scanner_bounds_non_source_reads_but_preserves_file_analysis() {
    let directory = tempfile::tempdir().unwrap();
    let mut bytes = vec![0; (super::super::filesystem::MAX_NON_SOURCE_ANALYSIS_BYTES as usize) + 1];
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
