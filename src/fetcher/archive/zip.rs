use std::{
    io::{Cursor, Read},
    path::{Path, PathBuf},
};

use zip::ZipArchive;

use crate::{
    error::{Error, Result},
    fetcher::budget::AcquisitionDeadline,
    model::EngineLimits,
};

use super::support::{
    ExtractionStats, MaterializedPathKind, MaterializedPaths, account_extracted_bytes,
    create_extracted_directory, normalize_relative, open_extraction_root, write_extracted_file,
};

const ARCHIVE_NAME: &str = "zip";

// End of central directory (EOCD) record.
const EOCD_SIGNATURE: &[u8; 4] = b"PK\x05\x06";
const EOCD_SIZE: usize = 22;
const EOCD_ENTRY_COUNT_OFFSET: usize = 10;
const EOCD_ENTRY_COUNT_SIZE: usize = 2;
const EOCD_COMMENT_LENGTH_OFFSET: usize = 20;
const EOCD_COMMENT_LENGTH_SIZE: usize = 2;
const MAX_EOCD_COMMENT_SIZE: usize = u16::MAX as usize;

// ZIP64 EOCD locator record.
const ZIP64_LOCATOR_SIGNATURE: &[u8; 4] = b"PK\x06\x07";
const ZIP64_LOCATOR_SIZE: usize = 20;
const ZIP64_LOCATOR_RECORD_OFFSET: usize = 8;
const ZIP64_LOCATOR_RECORD_OFFSET_SIZE: usize = 8;

// ZIP64 EOCD record.
const ZIP64_EOCD_SIGNATURE: &[u8; 4] = b"PK\x06\x06";
const ZIP64_EOCD_HEADER_SIZE: usize = 12;
const ZIP64_EOCD_MINIMUM_DATA_SIZE: u64 = 44;
const ZIP64_EOCD_MINIMUM_SIZE: usize =
    ZIP64_EOCD_HEADER_SIZE + ZIP64_EOCD_MINIMUM_DATA_SIZE as usize;
const ZIP64_EOCD_SIZE_OFFSET: usize = 4;
const ZIP64_EOCD_SIZE_SIZE: usize = 8;
const ZIP64_EOCD_ENTRY_COUNT_OFFSET: usize = 32;
const ZIP64_EOCD_ENTRY_COUNT_SIZE: usize = 8;

const UNIX_FILE_TYPE_MASK: u32 = 0o170000;
const UNIX_NO_FILE_TYPE: u32 = 0;
const UNIX_DIRECTORY_TYPE: u32 = 0o040000;
const UNIX_REGULAR_FILE_TYPE: u32 = 0o100000;
const UNIX_SYMLINK_TYPE: u32 = 0o120000;

fn zip_error(message: impl Into<String>) -> Error {
    Error::Extraction {
        archive: PathBuf::from(ARCHIVE_NAME),
        message: message.into(),
    }
}

pub fn entry_count(bytes: &[u8], deadline: &AcquisitionDeadline) -> Result<u64> {
    deadline.check()?;
    let eocd = find_eocd(bytes)?;
    let total_entries = eocd_entry_count(bytes, eocd);

    let entries = if total_entries == u16::MAX {
        zip64_entry_count(bytes, eocd)?
    } else {
        u64::from(total_entries)
    };
    deadline.check()?;
    Ok(entries)
}

fn find_eocd(bytes: &[u8]) -> Result<usize> {
    let search_start = bytes
        .len()
        .saturating_sub(EOCD_SIZE + MAX_EOCD_COMMENT_SIZE);

    bytes[search_start..]
        .windows(EOCD_SIGNATURE.len())
        .enumerate()
        .rev()
        .find_map(|(index, signature)| {
            (signature == EOCD_SIGNATURE).then_some(search_start + index)
        })
        .filter(|offset| {
            bytes
                .get(
                    offset + EOCD_COMMENT_LENGTH_OFFSET
                        ..offset + EOCD_COMMENT_LENGTH_OFFSET + EOCD_COMMENT_LENGTH_SIZE,
                )
                .map(|comment| {
                    let length = u16::from_le_bytes(comment.try_into().unwrap()) as usize;
                    offset + EOCD_SIZE + length == bytes.len()
                })
                .unwrap_or(false)
        })
        .ok_or_else(|| zip_error("missing or malformed ZIP end of central directory"))
}

fn eocd_entry_count(bytes: &[u8], eocd: usize) -> u16 {
    u16::from_le_bytes(
        bytes[eocd + EOCD_ENTRY_COUNT_OFFSET
            ..eocd + EOCD_ENTRY_COUNT_OFFSET + EOCD_ENTRY_COUNT_SIZE]
            .try_into()
            .unwrap(),
    )
}

fn zip64_entry_count(bytes: &[u8], eocd: usize) -> Result<u64> {
    let locator = bytes
        .get(
            eocd.checked_sub(ZIP64_LOCATOR_SIZE)
                .ok_or_else(|| zip_error("missing ZIP64 locator"))?..eocd,
        )
        .filter(|locator| locator[..ZIP64_LOCATOR_SIGNATURE.len()] == *ZIP64_LOCATOR_SIGNATURE)
        .ok_or_else(|| zip_error("missing or malformed ZIP64 locator"))?;
    let record_offset = u64::from_le_bytes(
        locator[ZIP64_LOCATOR_RECORD_OFFSET
            ..ZIP64_LOCATOR_RECORD_OFFSET + ZIP64_LOCATOR_RECORD_OFFSET_SIZE]
            .try_into()
            .unwrap(),
    );
    let record_offset = usize::try_from(record_offset)
        .map_err(|_| zip_error("ZIP64 end of central directory offset is too large"))?;
    let record = bytes
        .get(record_offset..)
        .filter(|record| {
            record.len() >= ZIP64_EOCD_MINIMUM_SIZE
                && record[..ZIP64_EOCD_SIGNATURE.len()] == *ZIP64_EOCD_SIGNATURE
        })
        .ok_or_else(|| zip_error("missing or malformed ZIP64 end of central directory"))?;
    let record_size = u64::from_le_bytes(
        record[ZIP64_EOCD_SIZE_OFFSET..ZIP64_EOCD_SIZE_OFFSET + ZIP64_EOCD_SIZE_SIZE]
            .try_into()
            .unwrap(),
    );
    let record_end = record_offset
        .checked_add(ZIP64_EOCD_HEADER_SIZE)
        .and_then(|offset| offset.checked_add(usize::try_from(record_size).ok()?))
        .ok_or_else(|| zip_error("ZIP64 end of central directory size is invalid"))?;
    if record_size < ZIP64_EOCD_MINIMUM_DATA_SIZE || record_end > bytes.len() {
        return Err(zip_error(
            "missing or malformed ZIP64 end of central directory",
        ));
    }

    Ok(u64::from_le_bytes(
        record[ZIP64_EOCD_ENTRY_COUNT_OFFSET
            ..ZIP64_EOCD_ENTRY_COUNT_OFFSET + ZIP64_EOCD_ENTRY_COUNT_SIZE]
            .try_into()
            .unwrap(),
    ))
}

pub fn preflight(
    bytes: &[u8],
    limits: &EngineLimits,
    deadline: &AcquisitionDeadline,
) -> Result<ExtractionStats> {
    let entries = entry_count(bytes, deadline)?;
    if entries > limits.max_extracted_files {
        return Err(Error::LimitExceeded {
            resource: "extracted files".to_owned(),
            limit: limits.max_extracted_files,
        });
    }

    let mut archive = ZipArchive::new(Cursor::new(bytes))
        .map_err(|archive_error| zip_error(archive_error.to_string()))?;
    let mut stats = ExtractionStats::default();
    let mut paths = MaterializedPaths::default();
    for index in 0..archive.len() {
        deadline.check()?;
        let mut entry = archive
            .by_index(index)
            .map_err(|archive_error| zip_error(archive_error.to_string()))?;
        let path = validate_entry(&entry, limits.max_file_depth)?;
        let path_kind = if entry.is_dir() {
            MaterializedPathKind::Directory
        } else {
            MaterializedPathKind::File
        };
        paths.account(
            &mut stats,
            &path,
            path_kind,
            limits,
            Path::new(ARCHIVE_NAME),
        )?;
        let entry_size = entry.size();
        account_extracted_bytes(&mut stats, entry_size, limits)?;
        verify_entry_size(&mut entry, entry_size, deadline)?;
    }
    deadline.check()?;
    Ok(stats)
}

pub fn extract(
    bytes: &[u8],
    destination: &Path,
    limits: &EngineLimits,
    deadline: &AcquisitionDeadline,
) -> Result<ExtractionStats> {
    let stats = preflight(bytes, limits, deadline)?;
    let root = open_extraction_root(destination)?;
    let mut archive = ZipArchive::new(Cursor::new(bytes))
        .map_err(|archive_error| zip_error(archive_error.to_string()))?;

    for index in 0..archive.len() {
        deadline.check()?;
        let mut entry = archive
            .by_index(index)
            .map_err(|archive_error| zip_error(archive_error.to_string()))?;
        let path = entry_path(&entry, limits.max_file_depth)?;
        let output = destination.join(&path);
        if entry.is_dir() {
            create_extracted_directory(&root, destination, &output)?;
        } else {
            let entry_size = entry.size();
            write_extracted_file(
                &mut entry,
                entry_size,
                &root,
                destination,
                &output,
                Path::new(ARCHIVE_NAME),
                deadline,
            )?;
        }
    }
    deadline.check()?;
    Ok(stats)
}

fn validate_entry(
    entry: &zip::read::ZipFile<'_, Cursor<&[u8]>>,
    max_file_depth: usize,
) -> Result<PathBuf> {
    let path = entry_path(entry, max_file_depth)?;
    if let Some(mode) = entry.unix_mode() {
        let file_type = mode & UNIX_FILE_TYPE_MASK;
        if file_type == UNIX_SYMLINK_TYPE {
            return Err(zip_error(format!("symlink rejected: {}", path.display())));
        }
        if !matches!(
            file_type,
            UNIX_NO_FILE_TYPE | UNIX_DIRECTORY_TYPE | UNIX_REGULAR_FILE_TYPE
        ) {
            return Err(zip_error(format!(
                "special file rejected: {}",
                path.display()
            )));
        }
    }
    Ok(path)
}

fn entry_path(
    entry: &zip::read::ZipFile<'_, Cursor<&[u8]>>,
    max_file_depth: usize,
) -> Result<PathBuf> {
    let path = entry
        .enclosed_name()
        .ok_or_else(|| zip_error(format!("unsafe path {}", entry.name())))?;
    normalize_relative(&path, max_file_depth).ok_or_else(|| {
        zip_error(format!(
            "unsafe or excessively deep path {}",
            path.display()
        ))
    })
}

fn verify_entry_size(
    entry: &mut zip::read::ZipFile<'_, Cursor<&[u8]>>,
    expected_size: u64,
    deadline: &AcquisitionDeadline,
) -> Result<()> {
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    while copied < expected_size {
        deadline.check()?;
        let remaining = expected_size - copied;
        let maximum = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let read = entry
            .read(&mut buffer[..maximum])
            .map_err(|error| zip_error(error.to_string()))?;
        if read == 0 {
            break;
        }
        copied += read as u64;
    }
    if copied != expected_size {
        return Err(zip_error(format!(
            "archive entry {} has {copied} bytes, expected {expected_size}",
            entry.name()
        )));
    }

    deadline.check()?;
    let mut extra = [0];
    if entry
        .read(&mut extra)
        .map_err(|error| zip_error(error.to_string()))?
        == 0
    {
        return Ok(());
    }

    let message = match expected_size.checked_add(1) {
        Some(minimum_size) => format!(
            "archive entry {} has at least {minimum_size} bytes, expected {expected_size}",
            entry.name()
        ),
        None => format!(
            "archive entry {} has more than {expected_size} bytes",
            entry.name()
        ),
    };
    Err(zip_error(message))
}
