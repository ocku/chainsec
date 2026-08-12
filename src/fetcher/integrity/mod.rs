use base64::{Engine as _, engine::general_purpose::STANDARD};

use sha2::{Digest, Sha256, Sha512};

use crate::{
    error::{Error, Result},
    fetcher::network::diagnostic_url,
};
use url::Url;

const ARTIFACT_VERIFICATION: &str = "artifact verification";

fn diagnostic_source(source: &str) -> String {
    Url::parse(source)
        .map(|url| diagnostic_url(&url))
        .unwrap_or_else(|_| source.to_owned())
}

fn matches_sha256_hex(bytes: &[u8], expected: &str) -> bool {
    expected.len() == 64
        && expected.bytes().all(|byte| byte.is_ascii_hexdigit())
        && hex::encode(Sha256::digest(bytes)).eq_ignore_ascii_case(expected)
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SriAlgorithm {
    Sha256,
    Sha512,
}

fn parse_sri_token(token: &str) -> Option<(SriAlgorithm, Vec<u8>)> {
    let (algorithm, encoded, digest_bytes) = if let Some(encoded) = token.strip_prefix("sha256-") {
        (SriAlgorithm::Sha256, encoded, 32)
    } else if let Some(encoded) = token.strip_prefix("sha512-") {
        (SriAlgorithm::Sha512, encoded, 64)
    } else {
        return None;
    };

    STANDARD
        .decode(encoded)
        .ok()
        .filter(|digest| digest.len() == digest_bytes)
        .map(|digest| (algorithm, digest))
}

pub(super) fn supported_npm_integrity(integrity: &str) -> bool {
    integrity
        .split_whitespace()
        .any(|token| parse_sri_token(token).is_some())
}

fn matches_sri(bytes: &[u8], expected: &str) -> bool {
    let tokens: Vec<_> = expected
        .split_whitespace()
        .filter_map(parse_sri_token)
        .collect();
    let Some(strongest) = tokens.iter().map(|(algorithm, _)| *algorithm).max() else {
        return false;
    };
    let actual = match strongest {
        SriAlgorithm::Sha256 => Sha256::digest(bytes).to_vec(),
        SriAlgorithm::Sha512 => Sha512::digest(bytes).to_vec(),
    };

    tokens
        .iter()
        .any(|(algorithm, digest)| *algorithm == strongest && digest.as_slice() == actual)
}

fn matches_integrity(bytes: &[u8], expected: &str) -> bool {
    let colon_sha256 = expected
        .split_whitespace()
        .filter_map(|token| token.strip_prefix("sha256:"))
        .collect::<Vec<_>>();
    if !colon_sha256.is_empty() {
        return colon_sha256
            .into_iter()
            .any(|digest| matches_sha256_hex(bytes, digest));
    }
    if matches_sha256_hex(bytes, expected) {
        true
    } else {
        matches_sri(bytes, expected)
    }
}

pub(super) fn verify_integrity(bytes: &[u8], expected: Option<&str>, source: &str) -> Result<()> {
    let Some(expected) = expected else {
        return Err(Error::Policy {
            operation: ARTIFACT_VERIFICATION.to_owned(),
            message: format!("{} has no expected integrity", diagnostic_source(source)),
        });
    };
    if matches_integrity(bytes, expected) {
        Ok(())
    } else {
        Err(Error::Fetch {
            package: "artifact".to_owned(),
            source_url: diagnostic_source(source),
            message: "integrity verification failed or uses an unsupported format".to_owned(),
        })
    }
}

pub(super) fn verify_jsr_checksum(bytes: &[u8], expected: &str, source: &str) -> Result<()> {
    if expected
        .strip_prefix("sha256-")
        .is_some_and(|value| matches_sha256_hex(bytes, value))
    {
        Ok(())
    } else {
        Err(Error::Fetch {
            package: "jsr package".to_owned(),
            source_url: diagnostic_source(source),
            message: "JSR file checksum verification failed or uses an unsupported format"
                .to_owned(),
        })
    }
}

#[cfg(test)]
mod tests;
