use std::{
    fs,
    io::Cursor,
    path::{Path, PathBuf},
};

use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use xz2::read::XzDecoder;

use crate::error::{Error, Result};
use crate::model::EngineLimits;

mod support;
mod tar;
mod zip;

pub(super) use support::{
    ExtractionStats, account_extracted_bytes, account_extracted_entry, safe_relative,
};
#[cfg(test)]
pub(super) use tar::extract as extract_tar;
#[cfg(test)]
pub(super) use zip::{extract as extract_zip, preflight as preflight_zip_entry_count};

pub(super) fn extract(
    bytes: &[u8],
    name: &str,
    destination: &Path,
    limits: &EngineLimits,
) -> Result<ExtractionStats> {
    if is_zip(bytes) {
        zip::extract(bytes, destination, limits)
    } else if bytes.starts_with(&[0x1f, 0x8b]) {
        tar::extract(
            GzDecoder::new(Cursor::new(bytes)),
            name,
            destination,
            limits,
        )
    } else if bytes.starts_with(b"BZh") {
        tar::extract(
            BzDecoder::new(Cursor::new(bytes)),
            name,
            destination,
            limits,
        )
    } else if bytes.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        tar::extract(
            XzDecoder::new(Cursor::new(bytes)),
            name,
            destination,
            limits,
        )
    } else if is_tar(bytes) {
        tar::extract(Cursor::new(bytes), name, destination, limits)
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

pub(super) fn single_root_or_self(source: &Path) -> Result<PathBuf> {
    let entries = fs::read_dir(source)
        .map_err(|source_error| Error::Io {
            operation: "inspect extraction root".to_owned(),
            path: source.to_owned(),
            source: source_error,
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|source_error| Error::Io {
            operation: "inspect extraction root".to_owned(),
            path: source.to_owned(),
            source: source_error,
        })?;
    if entries.len() == 1 && entries[0].path().is_dir() {
        Ok(entries[0].path())
    } else {
        Ok(source.to_owned())
    }
}

#[cfg(test)]
mod tests;
