use base64::{Engine as _, engine::general_purpose::STANDARD};

use sha2::{Digest, Sha256, Sha512};

use crate::{
    error::{Error, Result},
    fetcher::{budget::AcquisitionDeadline, network::diagnostic_url},
};
use url::Url;

const ARTIFACT_VERIFICATION: &str = "artifact verification";

fn diagnostic_source(source: &str) -> String {
    Url::parse(source)
        .map(|url| diagnostic_url(&url))
        .unwrap_or_else(|_| source.to_owned())
}

fn hash_chunks<D: Digest + Default>(
    bytes: &[u8],
    deadline: Option<&AcquisitionDeadline>,
) -> Result<Vec<u8>> {
    let mut hasher = D::default();
    for chunk in bytes.chunks(64 * 1024) {
        if let Some(deadline) = deadline {
            deadline.check()?;
        }
        hasher.update(chunk);
    }
    if let Some(deadline) = deadline {
        deadline.check()?;
    }
    Ok(hasher.finalize().to_vec())
}

fn matches_sha256_hex(
    bytes: &[u8],
    expected: &str,
    deadline: Option<&AcquisitionDeadline>,
) -> Result<bool> {
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(false);
    }
    Ok(hex::encode(hash_chunks::<Sha256>(bytes, deadline)?).eq_ignore_ascii_case(expected))
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

fn matching_sri_digest(
    bytes: &[u8],
    expected: &str,
    deadline: Option<&AcquisitionDeadline>,
) -> Result<Option<String>> {
    let tokens: Vec<_> = expected
        .split_whitespace()
        .filter_map(parse_sri_token)
        .collect();
    let Some(strongest) = tokens.iter().map(|(algorithm, _)| *algorithm).max() else {
        return Ok(None);
    };
    let (name, actual) = match strongest {
        SriAlgorithm::Sha256 => ("sha256", hash_chunks::<Sha256>(bytes, deadline)?),
        SriAlgorithm::Sha512 => ("sha512", hash_chunks::<Sha512>(bytes, deadline)?),
    };

    Ok(tokens
        .iter()
        .any(|(algorithm, digest)| *algorithm == strongest && digest.as_slice() == actual)
        .then(|| format!("{name}-{}", STANDARD.encode(actual))))
}

fn matching_integrity_digest(
    bytes: &[u8],
    expected: &str,
    deadline: Option<&AcquisitionDeadline>,
) -> Result<Option<String>> {
    let colon_sha256: Vec<_> = expected
        .split_whitespace()
        .filter_map(|token| token.strip_prefix("sha256:"))
        .collect();
    if !colon_sha256.is_empty() {
        let actual = hex::encode(hash_chunks::<Sha256>(bytes, deadline)?);
        return Ok(colon_sha256
            .into_iter()
            .any(|digest| digest.eq_ignore_ascii_case(&actual))
            .then(|| format!("sha256:{actual}")));
    }
    if expected.len() == 64 && expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        let actual = hex::encode(hash_chunks::<Sha256>(bytes, deadline)?);
        return Ok(actual
            .eq_ignore_ascii_case(expected)
            .then(|| format!("sha256:{actual}")));
    }
    matching_sri_digest(bytes, expected, deadline)
}

#[cfg(test)]
pub(super) fn verify_integrity_digest(
    bytes: &[u8],
    expected: Option<&str>,
    source: &str,
) -> Result<String> {
    verify_integrity_digest_inner(bytes, expected, source, None)
}

pub(super) fn verify_integrity_digest_before(
    bytes: &[u8],
    expected: Option<&str>,
    source: &str,
    deadline: &AcquisitionDeadline,
) -> Result<String> {
    verify_integrity_digest_inner(bytes, expected, source, Some(deadline))
}

fn verify_integrity_digest_inner(
    bytes: &[u8],
    expected: Option<&str>,
    source: &str,
    deadline: Option<&AcquisitionDeadline>,
) -> Result<String> {
    let Some(expected) = expected else {
        return Err(Error::Policy {
            operation: ARTIFACT_VERIFICATION.to_owned(),
            message: format!("{} has no expected integrity", diagnostic_source(source)),
        });
    };
    matching_integrity_digest(bytes, expected, deadline)?.ok_or_else(|| Error::Fetch {
        package: "artifact".to_owned(),
        source_url: diagnostic_source(source),
        message: "integrity verification failed or uses an unsupported format".to_owned(),
    })
}

#[cfg(test)]
pub(super) fn verify_integrity(bytes: &[u8], expected: Option<&str>, source: &str) -> Result<()> {
    verify_integrity_digest(bytes, expected, source).map(|_| ())
}

pub(super) fn verify_integrity_before(
    bytes: &[u8],
    expected: Option<&str>,
    source: &str,
    deadline: &AcquisitionDeadline,
) -> Result<()> {
    verify_integrity_digest_before(bytes, expected, source, deadline).map(|_| ())
}

pub(super) fn sha256_digest_before(bytes: &[u8], deadline: &AcquisitionDeadline) -> Result<String> {
    Ok(format!(
        "sha256:{}",
        hex::encode(hash_chunks::<Sha256>(bytes, Some(deadline))?)
    ))
}

pub(super) fn sha256_digest_raw_before(
    bytes: &[u8],
    deadline: &AcquisitionDeadline,
) -> Result<[u8; 32]> {
    let raw = hash_chunks::<Sha256>(bytes, Some(deadline))?;
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&raw);
    Ok(digest)
}

pub(super) fn verify_integrity_from_sha256_digest(
    digest: &[u8; 32],
    expected: Option<&str>,
    source: &str,
    deadline: &AcquisitionDeadline,
) -> Result<Option<()>> {
    deadline.check()?;
    let Some(expected) = expected else {
        return Err(Error::Policy {
            operation: ARTIFACT_VERIFICATION.to_owned(),
            message: format!("{} has no expected integrity", diagnostic_source(source)),
        });
    };
    let colon_sha256: Vec<_> = expected
        .split_whitespace()
        .filter_map(|token| token.strip_prefix("sha256:"))
        .collect();
    if !colon_sha256.is_empty() {
        let actual = hex::encode(digest);
        if colon_sha256
            .into_iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(&actual))
        {
            return Ok(Some(()));
        }
        return Err(Error::Fetch {
            package: "artifact".to_owned(),
            source_url: diagnostic_source(source),
            message: "integrity verification failed or uses an unsupported format".to_owned(),
        });
    }
    if expected.len() == 64 && expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        let actual = hex::encode(digest);
        if actual.eq_ignore_ascii_case(expected) {
            return Ok(Some(()));
        }
        return Err(Error::Fetch {
            package: "artifact".to_owned(),
            source_url: diagnostic_source(source),
            message: "integrity verification failed or uses an unsupported format".to_owned(),
        });
    }
    let tokens: Vec<_> = expected
        .split_whitespace()
        .filter_map(parse_sri_token)
        .collect();
    let Some(strongest) = tokens.iter().map(|(algorithm, _)| *algorithm).max() else {
        return Err(Error::Fetch {
            package: "artifact".to_owned(),
            source_url: diagnostic_source(source),
            message: "integrity verification failed or uses an unsupported format".to_owned(),
        });
    };
    match strongest {
        SriAlgorithm::Sha256 => {
            if tokens
                .iter()
                .any(|(algorithm, d)| *algorithm == SriAlgorithm::Sha256 && d.as_slice() == digest)
            {
                Ok(Some(()))
            } else {
                Err(Error::Fetch {
                    package: "artifact".to_owned(),
                    source_url: diagnostic_source(source),
                    message: "integrity verification failed or uses an unsupported format"
                        .to_owned(),
                })
            }
        }
        SriAlgorithm::Sha512 => Ok(None),
    }
}

pub(super) fn verify_jsr_checksum_before(
    bytes: &[u8],
    expected: &str,
    source: &str,
    deadline: &AcquisitionDeadline,
) -> Result<()> {
    verify_jsr_checksum_inner(bytes, expected, source, Some(deadline))
}

fn verify_jsr_checksum_inner(
    bytes: &[u8],
    expected: &str,
    source: &str,
    deadline: Option<&AcquisitionDeadline>,
) -> Result<()> {
    if let Some(value) = expected.strip_prefix("sha256-")
        && matches_sha256_hex(bytes, value, deadline)?
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
