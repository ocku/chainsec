use std::path::Path;

use super::entropy::shannon_entropy;
use crate::model::{AnalysisPoint, Confidence, FindingType, Location, Risk};

const MIN_HIGH_ENTROPY_BYTES: usize = 256;
const HIGH_ENTROPY_THRESHOLD: f64 = 7.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileKind {
    Compressed(&'static str),
    Binary,
    HighEntropy,
}

pub fn analyze_with_size(
    path: &Path,
    package: &str,
    bytes: &[u8],
    file_size: u64,
) -> Option<AnalysisPoint> {
    let kind = classify_file(path, bytes)?;
    let (rule_id, rationale, remediation, matched_code, risk, confidence) =
        finding_details(kind, bytes, file_size);

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
        package: package.to_owned(),
        file: path.to_owned(),
        location,
        matched_code: matched_code.to_owned(),
        suppressed: false,
    })
}

fn classify_file(path: &Path, bytes: &[u8]) -> Option<FileKind> {
    if let Some(format) = compression_format(bytes) {
        return Some(FileKind::Compressed(format));
    }

    if is_known_static_asset(path, bytes) {
        return None;
    }

    if bytes.len() >= MIN_HIGH_ENTROPY_BYTES
        && shannon_entropy(bytes.iter().copied()) >= HIGH_ENTROPY_THRESHOLD
    {
        return Some(FileKind::HighEntropy);
    }

    is_binary(bytes).then_some(FileKind::Binary)
}

fn finding_details(
    kind: FileKind,
    bytes: &[u8],
    file_size: u64,
) -> (&'static str, String, &'static str, String, Risk, Confidence) {
    match kind {
        FileKind::Compressed(format) => (
            "FILE_COMPRESSED",
            format!(
                "The file is compressed ({format}), which can conceal payloads from source analysis."
            ),
            "Inspect the archive contents and provenance before trusting or executing the file.",
            format!("compressed format: {format}, size: {file_size} bytes"),
            Risk::High,
            Confidence::High,
        ),
        FileKind::Binary => (
            "FILE_BINARY",
            "The file contains binary data and cannot be fully inspected by the source analyser.".to_owned(),
            "Inspect the file with an appropriate binary analyser and verify its provenance.",
            format!("binary file, size: {file_size} bytes"),
            Risk::High,
            Confidence::High,
        ),
        FileKind::HighEntropy => (
            "FILE_HIGH_ENTROPY",
            "The file has unusually high Shannon entropy and may contain encrypted, packed, or compressed data without a recognized signature.".to_owned(),
            "Inspect the file contents and provenance; do not execute opaque data without review.",
            format!(
                "high-entropy file, size: {file_size} bytes, entropy: {:.2} bits/byte",
                shannon_entropy(bytes.iter().copied())
            ),
            Risk::Medium,
            Confidence::Medium,
        ),
    }
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
    fn recognizes_compressed_formats_before_binary_detection() {
        let finding =
            analyze_with_size(Path::new("payload.gz"), "root", &[0x1f, 0x8b, 0, 1], 4).unwrap();
        assert_eq!(finding.rule_id, "FILE_COMPRESSED");
        assert!(finding.matched_code.contains("gzip"));
    }

    #[test]
    fn recognizes_binary_files() {
        let finding =
            analyze_with_size(Path::new("payload.bin"), "root", &[0, 1, 2, 3], 4).unwrap();
        assert_eq!(finding.rule_id, "FILE_BINARY");
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
        assert_eq!(finding.rule_id, "FILE_BINARY");
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
            "FILE_HIGH_ENTROPY"
        );
    }
}
