use std::path::Path;

#[cfg(test)]
use super::entropy::shannon_entropy;
use crate::model::{AnalysisPoint, Confidence, FindingType, Location, Risk};

const MIN_HIGH_ENTROPY_BYTES: usize = 256;
const HIGH_ENTROPY_THRESHOLD: f64 = 7.0;

#[derive(Debug, Clone, Copy, PartialEq)]
enum FileKind {
    Compressed(&'static str),
    NativeArtifact(&'static str),
    Binary,
    HighEntropy(f64),
}

pub fn analyze_with_size(
    path: &Path,
    package: &str,
    bytes: &[u8],
    file_size: u64,
) -> Option<AnalysisPoint> {
    let kind = classify_file(path, bytes)?;
    let (rule_id, rationale, remediation, matched_code, risk, confidence) =
        finding_details(kind, file_size);

    let location = Location {
        start_line: 1,
        start_column: 1,
        end_line: 1,
        end_column: 1,
    };
    let file = path.to_string_lossy();
    Some(AnalysisPoint {
        id: AnalysisPoint::stable_id(rule_id, 1, package, &file, &location, &matched_code),
        rule_id: rule_id.to_owned(),
        rule_version: 1,
        finding_type: FindingType::FileAnalysis,
        risk,
        confidence,
        rationale,
        remediation: remediation.to_owned(),
        capability: None,
        package: package.to_owned(),
        file: path.to_owned(),
        location,
        matched_code: matched_code.to_owned(),
        suppressed: false,
        suppression: None,
    })
}

fn classify_file(path: &Path, bytes: &[u8]) -> Option<FileKind> {
    if let Some(format) = compression_format(bytes) {
        return Some(FileKind::Compressed(format));
    }

    if is_known_static_asset(path, bytes) {
        return None;
    }

    if let Some(format) = native_artifact_format(bytes) {
        return Some(FileKind::NativeArtifact(format));
    }

    if bytes.len() >= MIN_HIGH_ENTROPY_BYTES {
        let entropy = shannon_entropy_bytes(bytes);
        if entropy >= HIGH_ENTROPY_THRESHOLD {
            return Some(FileKind::HighEntropy(entropy));
        }
    }

    is_binary(bytes).then_some(FileKind::Binary)
}

fn finding_details(
    kind: FileKind,
    file_size: u64,
) -> (&'static str, String, &'static str, String, Risk, Confidence) {
    match kind {
        FileKind::Compressed(format) => (
            "chainsec.detection.file.compressed",
            format!(
                "The file is compressed ({format}), which can conceal payloads from source analysis."
            ),
            "Inspect the archive contents and provenance before trusting or executing the file.",
            format!("compressed format: {format}, size: {file_size} bytes"),
            Risk::High,
            Confidence::High,
        ),
        FileKind::NativeArtifact(format) => (
            "chainsec.detection.file.native-artifact",
            format!(
                "The file is a recognized {format} native executable or library artifact. It was not source-analysed."
            ),
            "Verify the artifact's package provenance and platform relevance; inspect it with a native-code analyser when needed.",
            format!("native artifact: {format}, size: {file_size} bytes"),
            Risk::High,
            Confidence::High,
        ),
        FileKind::Binary => (
            "chainsec.detection.file.binary",
            "The file contains unrecognized binary data and cannot be fully inspected by the source analyser.".to_owned(),
            "Inspect the file with an appropriate binary analyser and verify its provenance.",
            format!("binary file, size: {file_size} bytes"),
            Risk::High,
            Confidence::High,
        ),
        FileKind::HighEntropy(entropy) => (
            "chainsec.detection.file.high-entropy-file",
            "The file has unusually high Shannon entropy and may contain encrypted, packed, or compressed data without a recognized signature.".to_owned(),
            "Inspect the file contents and provenance; do not execute opaque data without review.",
            format!(
                "high-entropy file, size: {file_size} bytes, entropy: {:.2} bits/byte",
                entropy
            ),
            Risk::Medium,
            Confidence::Medium,
        ),
    }
}

fn shannon_entropy_bytes(bytes: &[u8]) -> f64 {
    let mut frequencies = [0usize; 256];
    for byte in bytes {
        frequencies[*byte as usize] += 1;
    }

    let length = bytes.len() as f64;
    frequencies.into_iter().fold(0.0, |entropy, count| {
        if count == 0 {
            return entropy;
        }
        let probability = count as f64 / length;
        entropy - probability * probability.log2()
    })
}

fn compression_format(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0x1f, 0x8b]) {
        Some("gzip")
    } else if bytes.starts_with(b"BZh") {
        Some("bzip2")
    } else if bytes.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        Some("xz")
    } else if bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Some("zstd")
    } else if bytes.starts_with(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) {
        Some("7z")
    } else if bytes.starts_with(b"Rar!\x1a\x07") {
        Some("RAR")
    } else if bytes.starts_with(b"LZIP") {
        Some("lzip")
    } else if bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08")
    {
        Some("ZIP")
    } else {
        None
    }
}

fn native_artifact_format(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x7fELF") {
        Some("ELF")
    } else if matches!(
        bytes.get(..4),
        Some(
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xcf, 0xfa, 0xed, 0xfe]
                | [0xca, 0xfe, 0xba, 0xbe]
                | [0xbe, 0xba, 0xfe, 0xca]
        )
    ) {
        Some("Mach-O")
    } else if is_pe_executable(bytes) {
        Some("PE")
    } else if bytes.starts_with(b"\0asm") {
        Some("WebAssembly")
    } else {
        None
    }
}

fn is_pe_executable(bytes: &[u8]) -> bool {
    if !bytes.starts_with(b"MZ") || bytes.len() < 0x40 {
        return false;
    }

    let offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    bytes.get(offset..offset + 4) == Some(b"PE\0\0")
}

fn is_known_static_asset(path: &Path, bytes: &[u8]) -> bool {
    let extension = path.extension().and_then(|extension| extension.to_str());
    match extension
        .map(|extension| extension.to_ascii_lowercase())
        .as_deref()
    {
        Some("png") => bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
        Some("jpg" | "jpeg") => bytes.starts_with(&[0xff, 0xd8, 0xff]),
        Some("gif") => bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a"),
        Some("webp") => bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP"),
        Some("ico") => bytes.starts_with(&[0, 0, 1, 0]),
        Some("bmp") => bytes.starts_with(b"BM"),
        Some("icns") => bytes.starts_with(b"icns"),
        _ => false,
    }
}

fn is_binary(bytes: &[u8]) -> bool {
    bytes.contains(&0) || std::str::from_utf8(bytes).is_err()
}

#[cfg(test)]
mod tests {
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
        assert_eq!(finding.rule_id, "chainsec.detection.file.compressed");
        assert!(finding.matched_code.contains("gzip"));
    }

    #[test]
    fn recognizes_unidentified_binary_files() {
        let finding =
            analyze_with_size(Path::new("payload.bin"), "root", &[0, 1, 2, 3], 4).unwrap();
        assert_eq!(finding.rule_id, "chainsec.detection.file.binary");
        assert_eq!(finding.risk, Risk::High);
    }

    #[test]
    fn classifies_recognized_native_artifacts_as_high_risk() {
        let elf =
            analyze_with_size(Path::new("addon.node"), "root", b"\x7fELF\x02\x01", 6).unwrap();
        assert_eq!(elf.rule_id, "chainsec.detection.file.native-artifact");
        assert_eq!(elf.risk, Risk::High);
        assert!(elf.matched_code.contains("ELF"));

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
        assert_eq!(pe.rule_id, "chainsec.detection.file.native-artifact");
        assert_eq!(pe.risk, Risk::High);
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
        let finding =
            analyze_with_size(Path::new("payload.png"), "root", &[0, 1, 2, 3], 4).unwrap();
        assert_eq!(finding.rule_id, "chainsec.detection.file.binary");
    }

    #[test]
    fn recognizes_high_entropy_files() {
        let bytes = (0..=255)
            .cycle()
            .take(MIN_HIGH_ENTROPY_BYTES)
            .collect::<Vec<_>>();
        assert_eq!(
            analyze_with_size(Path::new("payload.dat"), "root", &bytes, bytes.len() as u64)
                .unwrap()
                .rule_id,
            "chainsec.detection.file.high-entropy-file"
        );
    }
}
