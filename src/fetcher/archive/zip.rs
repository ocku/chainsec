use std::{
    collections::HashSet,
    io::Cursor,
    path::{Path, PathBuf},
};

use zip::ZipArchive;

use crate::{
    error::{Error, Result},
    model::EngineLimits,
};

use super::support::{
    ExtractionStats, account_extracted_entry, create_extracted_directory, open_extraction_root,
    reject_duplicate_path, safe_relative, write_extracted_file,
};

fn zip_error(message: impl Into<String>) -> Error {
    Error::Extraction {
        archive: PathBuf::from("zip"),
        message: message.into(),
    }
}

pub fn entry_count(bytes: &[u8]) -> Result<u64> {
    const EOCD: &[u8; 4] = b"PK\x05\x06";
    const ZIP64_LOCATOR: &[u8; 4] = b"PK\x06\x07";
    const ZIP64_EOCD: &[u8; 4] = b"PK\x06\x06";
    const EOCD_SIZE: usize = 22;
    const MAX_COMMENT: usize = u16::MAX as usize;

    let search_start = bytes.len().saturating_sub(EOCD_SIZE + MAX_COMMENT);
    let eocd = bytes[search_start..]
        .windows(EOCD.len())
        .enumerate()
        .rev()
        .find_map(|(index, signature)| (signature == EOCD).then_some(search_start + index))
        .filter(|offset| {
            bytes
                .get(offset + 20..offset + EOCD_SIZE)
                .map(|comment| {
                    let length = u16::from_le_bytes([comment[0], comment[1]]) as usize;
                    offset + EOCD_SIZE + length == bytes.len()
                })
                .unwrap_or(false)
        })
        .ok_or_else(|| zip_error("missing or malformed ZIP end of central directory"))?;

    let total_entries = u16::from_le_bytes(bytes[eocd + 10..eocd + 12].try_into().unwrap());
    if total_entries != u16::MAX {
        return Ok(u64::from(total_entries));
    }

    let locator = bytes
        .get(
            eocd.checked_sub(20)
                .ok_or_else(|| zip_error("missing ZIP64 locator"))?..eocd,
        )
        .filter(|locator| locator[..4] == *ZIP64_LOCATOR)
        .ok_or_else(|| zip_error("missing or malformed ZIP64 locator"))?;
    let record_offset = u64::from_le_bytes(locator[8..16].try_into().unwrap());
    let record_offset = usize::try_from(record_offset)
        .map_err(|_| zip_error("ZIP64 end of central directory offset is too large"))?;
    let record = bytes
        .get(record_offset..)
        .filter(|record| record.len() >= 56 && record[..4] == *ZIP64_EOCD)
        .ok_or_else(|| zip_error("missing or malformed ZIP64 end of central directory"))?;
    let record_size = u64::from_le_bytes(record[4..12].try_into().unwrap());
    let record_end = record_offset
        .checked_add(12)
        .and_then(|offset| offset.checked_add(usize::try_from(record_size).ok()?))
        .ok_or_else(|| zip_error("ZIP64 end of central directory size is invalid"))?;
    if record_size < 44 || record_end > bytes.len() {
        return Err(zip_error(
            "missing or malformed ZIP64 end of central directory",
        ));
    }
    Ok(u64::from_le_bytes(record[32..40].try_into().unwrap()))
}

pub fn preflight(bytes: &[u8], limits: &EngineLimits) -> Result<()> {
    let entries = entry_count(bytes)?;
    if entries > limits.max_extracted_files {
        return Err(Error::LimitExceeded {
            resource: "extracted files".to_owned(),
            limit: limits.max_extracted_files,
        });
    }
    Ok(())
}

pub fn extract(bytes: &[u8], destination: &Path, limits: &EngineLimits) -> Result<ExtractionStats> {
    preflight(bytes, limits)?;
    let root = open_extraction_root(destination)?;
    let mut archive = ZipArchive::new(Cursor::new(bytes))
        .map_err(|archive_error| zip_error(archive_error.to_string()))?;
    let mut stats = ExtractionStats::default();
    let mut seen = HashSet::new();

    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|archive_error| zip_error(archive_error.to_string()))?;
        let path = entry
            .enclosed_name()
            .ok_or_else(|| zip_error(format!("unsafe path {}", entry.name())))?
            .to_owned();
        if !safe_relative(&path) {
            return Err(zip_error(format!(
                "unsafe or excessively deep path {}",
                path.display()
            )));
        }
        reject_duplicate_path(&mut seen, &path, Path::new("zip"))?;
        if let Some(mode) = entry.unix_mode() {
            match mode & 0o170000 {
                0 | 0o040000 | 0o100000 => {}
                0o120000 => return Err(zip_error(format!("symlink rejected: {}", path.display()))),
                _ => {
                    return Err(zip_error(format!(
                        "special file rejected: {}",
                        path.display()
                    )));
                }
            }
        }
        let entry_size = entry.size();
        account_extracted_entry(&mut stats, entry_size, limits)?;
        let output = destination.join(&path);
        if entry.is_dir() {
            create_extracted_directory(&root, destination, &output)?;
        } else {
            write_extracted_file(
                &mut entry,
                entry_size,
                &root,
                destination,
                &output,
                Path::new("zip"),
            )?;
        }
    }
    Ok(stats)
}
