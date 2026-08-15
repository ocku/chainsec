use std::{
    io::Cursor,
    path::{Path, PathBuf},
};

use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use xz2::read::XzDecoder;

use crate::error::{Error, Result};
use crate::fetcher::budget::AcquisitionDeadline;
use crate::fetcher::filesystem::TrustedDir;
use crate::model::EngineLimits;

mod support;
mod tar;
mod zip;

pub(super) use support::{
    ExtractionStats, account_extracted_bytes, account_extracted_entry, safe_relative,
};
#[cfg(test)]
pub(super) fn extract_tar<R: std::io::Read>(
    reader: R,
    name: &str,
    destination: &Path,
    limits: &EngineLimits,
) -> Result<ExtractionStats> {
    tar::extract(reader, name, destination, limits, &test_deadline())
}

#[cfg(test)]
pub(super) fn extract_zip(
    bytes: &[u8],
    destination: &Path,
    limits: &EngineLimits,
) -> Result<ExtractionStats> {
    zip::extract(bytes, destination, limits, &test_deadline())
}

#[cfg(test)]
pub(super) fn preflight_zip_entry_count(
    bytes: &[u8],
    limits: &EngineLimits,
) -> Result<ExtractionStats> {
    zip::preflight(bytes, limits, &test_deadline())
}

#[cfg(test)]
fn test_deadline() -> AcquisitionDeadline {
    crate::fetcher::budget::AcquisitionBudget::new(std::time::Duration::from_secs(3_600), u64::MAX)
        .deadline_guard()
}

#[cfg(test)]
pub(super) fn extract(
    bytes: &[u8],
    name: &str,
    destination: &Path,
    limits: &EngineLimits,
) -> Result<ExtractionStats> {
    extract_before(bytes, name, destination, limits, &test_deadline())
}

pub(super) fn extract_before(
    bytes: &[u8],
    name: &str,
    destination: &Path,
    limits: &EngineLimits,
    deadline: &AcquisitionDeadline,
) -> Result<ExtractionStats> {
    deadline.check()?;
    if is_zip(bytes) {
        zip::extract(bytes, destination, limits, deadline)
    } else if bytes.starts_with(&[0x1f, 0x8b]) {
        tar::extract(
            GzDecoder::new(Cursor::new(bytes)),
            name,
            destination,
            limits,
            deadline,
        )
    } else if bytes.starts_with(b"BZh") {
        tar::extract(
            BzDecoder::new(Cursor::new(bytes)),
            name,
            destination,
            limits,
            deadline,
        )
    } else if bytes.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        tar::extract(
            XzDecoder::new(Cursor::new(bytes)),
            name,
            destination,
            limits,
            deadline,
        )
    } else if is_tar(bytes) {
        tar::extract(Cursor::new(bytes), name, destination, limits, deadline)
    } else {
        Err(Error::Extraction {
            archive: PathBuf::from(name),
            message: "unsupported archive format".to_owned(),
        })
    }
}

fn is_zip(bytes: &[u8]) -> bool {
    bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08")
}

fn is_tar(bytes: &[u8]) -> bool {
    let Some(header) = bytes.get(..512) else {
        return false;
    };
    if header.iter().all(|byte| *byte == 0) {
        return bytes
            .get(512..1024)
            .is_some_and(|block| block.iter().all(|byte| *byte == 0));
    }
    let Some(checksum) = header.get(148..156).and_then(parse_tar_octal) else {
        return false;
    };
    let actual = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum::<u64>();
    checksum == actual
}

fn parse_tar_octal(bytes: &[u8]) -> Option<u64> {
    let mut digits = bytes
        .iter()
        .copied()
        .skip_while(|byte| matches!(byte, b' ' | 0))
        .take_while(|byte| matches!(byte, b'0'..=b'7'))
        .peekable();
    digits.peek()?;
    Some(digits.fold(0u64, |value, byte| {
        value
            .saturating_mul(8)
            .saturating_add(u64::from(byte - b'0'))
    }))
}

/// When an archive extracts into a single top-level directory, returns that
/// directory; otherwise returns `source` unchanged.  Uses descriptor-relative
/// operations through [`TrustedDir`] so the enumeration and the directory
/// check are not vulnerable to TOCTOU.
pub(super) fn single_root_or_self_before(
    source: &Path,
    deadline: &AcquisitionDeadline,
) -> Result<PathBuf> {
    deadline.check()?;
    let directory = TrustedDir::open(source).map_err(|source_error| Error::Io {
        operation: "inspect extraction root".to_owned(),
        path: source.to_owned(),
        source: source_error,
    })?;
    // Only need to know whether there is exactly one child.
    let entries = directory
        .list_child_names_up_to(2)
        .map_err(|source_error| Error::Io {
            operation: "inspect extraction root".to_owned(),
            path: source.to_owned(),
            source: source_error,
        })?;
    deadline.check()?;
    if entries.len() == 1 {
        // Verify it is still a directory through the trusted handle so a
        // concurrent replacement (TOCTOU) cannot trick us.
        if directory.open_subdirectory(&entries[0]).is_ok() {
            return Ok(source.join(&entries[0]));
        }
    }
    Ok(source.to_owned())
}

#[cfg(test)]
mod tests;
