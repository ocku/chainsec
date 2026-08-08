use std::{
    fmt::Display,
    fs::File,
    io::{self, Read},
    path::Path,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256, Sha512};

use crate::{
    error::{Error, Result},
    model::EngineLimits,
};

const CACHE_VALIDATION: &str = "cache validation";
const ARTIFACT_VERIFICATION: &str = "artifact verification";

fn cache_validation_error(message: impl Display) -> Error {
    Error::Policy {
        operation: CACHE_VALIDATION.to_owned(),
        message: message.to_string(),
    }
}

fn cached_file_error(path: &Path, source: io::Error) -> Error {
    Error::Io {
        operation: "validate cached file".to_owned(),
        path: path.to_owned(),
        source,
    }
}

fn matches_sha256_hex(bytes: &[u8], expected: &str) -> bool {
    expected.len() == 64
        && expected.bytes().all(|byte| byte.is_ascii_hexdigit())
        && hex::encode(Sha256::digest(bytes)).eq_ignore_ascii_case(expected)
}

fn matches_integrity(bytes: &[u8], expected: &str) -> bool {
    if let Some(value) = expected.strip_prefix("sha256:") {
        matches_sha256_hex(bytes, value)
    } else if let Some(value) = expected.strip_prefix("sha256-") {
        STANDARD.encode(Sha256::digest(bytes)) == value
    } else if let Some(value) = expected.strip_prefix("sha512-") {
        STANDARD.encode(Sha512::digest(bytes)) == value
    } else {
        matches_sha256_hex(bytes, expected)
    }
}

pub(super) fn hash_tree(root: &Path, limits: &EngineLimits) -> Result<String> {
    let mut files = walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(cache_validation_error)?;
    files.sort_by(|left, right| left.path().cmp(right.path()));
    let mut digest = Sha256::new();
    let mut file_count = 0u64;
    let mut total = 0u64;
    for entry in files {
        if entry.file_type().is_symlink() {
            return Err(cache_validation_error(format!(
                "symlink rejected: {}",
                entry.path().display()
            )));
        }
        if !entry.file_type().is_file() {
            continue;
        }
        file_count = file_count.saturating_add(1);
        if file_count > limits.max_extracted_files {
            return Err(Error::LimitExceeded {
                resource: "cached source files".to_owned(),
                limit: limits.max_extracted_files,
            });
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(cache_validation_error)?;
        digest.update(relative.to_string_lossy().as_bytes());
        digest.update([0]);
        let mut file =
            File::open(entry.path()).map_err(|source| cached_file_error(entry.path(), source))?;
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let count = file
                .read(&mut buffer)
                .map_err(|source| cached_file_error(entry.path(), source))?;
            if count == 0 {
                break;
            }
            total = total.saturating_add(count as u64);
            if total > limits.max_extracted_bytes {
                return Err(Error::LimitExceeded {
                    resource: "cached source bytes".to_owned(),
                    limit: limits.max_extracted_bytes,
                });
            }
            digest.update(&buffer[..count]);
        }
        digest.update([0]);
    }
    Ok(format!("sha256:{}", hex::encode(digest.finalize())))
}

pub(super) fn verify_integrity(bytes: &[u8], expected: Option<&str>, source: &str) -> Result<()> {
    let Some(expected) = expected else {
        return Err(Error::Policy {
            operation: ARTIFACT_VERIFICATION.to_owned(),
            message: format!("{source} has no expected integrity"),
        });
    };
    if matches_integrity(bytes, expected) {
        Ok(())
    } else {
        Err(Error::Fetch {
            package: "artifact".to_owned(),
            source_url: source.to_owned(),
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
            source_url: source.to_owned(),
            message: "JSR file checksum verification failed or uses an unsupported format"
                .to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrity_is_checked() {
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(b"safe")));
        assert!(verify_integrity(b"safe", Some(&digest), "fixture").is_ok());
        assert!(verify_integrity(b"changed", Some(&digest), "fixture").is_err());
    }
}
