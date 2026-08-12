use super::*;

#[test]
fn byte_entropy_matches_the_generic_entropy_calculation() {
    let bytes = (0..=255).cycle().take(1024).collect::<Vec<_>>();
    assert!((shannon_entropy_bytes(&bytes) - shannon_entropy(bytes)).abs() < f64::EPSILON);
}

#[test]
fn recognizes_compressed_formats_before_binary_detection() {
    let finding =
        analyze_with_size(Path::new("payload.gz"), "root", &[0x1f, 0x8b, 0, 1], 4).unwrap();
    assert!(finding.is_exempt_in_test_fixture);
    assert_eq!(
        finding.finding.rule_id,
        "chainsec.detection.file.compressed"
    );
    assert!(finding.finding.matched_code.contains("gzip"));
}

#[test]
fn recognizes_unidentified_binary_files() {
    let finding = analyze_with_size(Path::new("payload.bin"), "root", &[0, 1, 2, 3], 4).unwrap();
    assert!(finding.is_exempt_in_test_fixture);
    assert_eq!(finding.finding.rule_id, "chainsec.detection.file.binary");
    assert_eq!(finding.finding.risk, Risk::High);
}

#[test]
fn distinguishes_legacy_encoded_text_from_binary_data() {
    let bytes = b"caf\xe9, na\xefve\n";
    let finding =
        analyze_with_size(Path::new("message.txt"), "root", bytes, bytes.len() as u64).unwrap();
    assert!(!finding.is_exempt_in_test_fixture);
    assert_eq!(
        finding.finding.rule_id,
        "chainsec.detection.file.non-utf8-text"
    );
    assert_eq!(finding.finding.risk, Risk::Medium);
}

#[test]
fn keeps_control_heavy_invalid_utf8_as_binary() {
    let bytes = [0x01, 0x02, 0x03, 0x80, 0x81, 0x82, 0x83, 0x84];
    let finding =
        analyze_with_size(Path::new("payload.bin"), "root", &bytes, bytes.len() as u64).unwrap();
    assert!(finding.is_exempt_in_test_fixture);
    assert_eq!(finding.finding.rule_id, "chainsec.detection.file.binary");
    assert_eq!(finding.finding.risk, Risk::High);
}

#[test]
fn classifies_recognized_native_artifacts_as_high_risk() {
    let elf = analyze_with_size(Path::new("addon.node"), "root", b"\x7fELF\x02\x01", 6).unwrap();
    assert!(!elf.is_exempt_in_test_fixture);
    assert_eq!(
        elf.finding.rule_id,
        "chainsec.detection.file.native-artifact"
    );
    assert_eq!(elf.finding.risk, Risk::High);
    assert!(elf.finding.matched_code.contains("ELF"));

    let mut pe_bytes = vec![0; 0x44];
    pe_bytes[..2].copy_from_slice(b"MZ");
    pe_bytes[0x3c..0x40].copy_from_slice(&0x40_u32.to_le_bytes());
    pe_bytes[0x40..].copy_from_slice(b"PE\0\0");
    let pe = analyze_with_size(
        Path::new("helper.exe"),
        "root",
        &pe_bytes,
        pe_bytes.len() as u64,
    )
    .unwrap();
    assert!(!pe.is_exempt_in_test_fixture);
    assert_eq!(
        pe.finding.rule_id,
        "chainsec.detection.file.native-artifact"
    );
    assert_eq!(pe.finding.risk, Risk::High);
}

#[test]
fn rejects_a_pe_header_with_an_overflowing_offset() {
    let mut bytes = vec![0; 0x40];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());

    assert!(!is_pe_executable(&bytes));
}

#[test]
fn ignores_recognized_static_assets() {
    assert!(
        analyze_with_size(
            Path::new("favicon.ico"),
            "root",
            &[0, 0, 1, 0, 1, 0, 0, 0],
            8,
        )
        .is_none()
    );
}

#[test]
fn does_not_trust_an_asset_extension_without_a_matching_signature() {
    let finding = analyze_with_size(Path::new("payload.png"), "root", &[0, 1, 2, 3], 4).unwrap();
    assert!(finding.is_exempt_in_test_fixture);
    assert_eq!(finding.finding.rule_id, "chainsec.detection.file.binary");
}

#[test]
fn recognizes_high_entropy_files() {
    let bytes = (0..=255)
        .cycle()
        .take(MIN_HIGH_ENTROPY_BYTES)
        .collect::<Vec<_>>();
    let finding =
        analyze_with_size(Path::new("payload.dat"), "root", &bytes, bytes.len() as u64).unwrap();
    assert!(!finding.is_exempt_in_test_fixture);
    assert_eq!(
        finding.finding.rule_id,
        "chainsec.detection.file.high-entropy-file"
    );
}
