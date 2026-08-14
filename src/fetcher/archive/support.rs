use std::{
    collections::HashSet,
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
};

use crate::{
    error::{Error, Result},
    fetcher::filesystem::TrustedDir,
    model::EngineLimits,
};

#[derive(Debug, Default)]
pub struct ExtractionStats {
    pub files: u64,
    pub bytes: u64,
}

pub fn safe_relative(path: &Path, max_file_depth: usize) -> bool {
    !path.is_absolute()
        && path.components().count() <= max_file_depth
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

pub fn check_extraction_limits(stats: &ExtractionStats, limits: &EngineLimits) -> Result<()> {
    if stats.files > limits.max_extracted_files {
        return Err(Error::LimitExceeded {
            resource: "extracted files".to_owned(),
            limit: limits.max_extracted_files,
        });
    }
    if stats.bytes > limits.max_extracted_size {
        return Err(Error::LimitExceeded {
            resource: "extracted bytes".to_owned(),
            limit: limits.max_extracted_size,
        });
    }
    Ok(())
}

pub fn reject_duplicate_path(
    seen: &mut HashSet<PathBuf>,
    path: &Path,
    archive: &Path,
) -> Result<()> {
    if seen.insert(path.to_owned()) {
        return Ok(());
    }

    Err(Error::Extraction {
        archive: archive.to_owned(),
        message: format!("duplicate path {}", path.display()),
    })
}

pub fn account_extracted_entry(
    stats: &mut ExtractionStats,
    declared_size: u64,
    limits: &EngineLimits,
) -> Result<()> {
    stats.files = stats.files.saturating_add(1);
    account_extracted_bytes(stats, declared_size, limits)
}

pub fn account_extracted_bytes(
    stats: &mut ExtractionStats,
    bytes: u64,
    limits: &EngineLimits,
) -> Result<()> {
    stats.bytes = stats.bytes.saturating_add(bytes);
    check_extraction_limits(stats, limits)
}

pub fn create_extracted_directory(
    root: &TrustedDir,
    destination: &Path,
    output: &Path,
) -> Result<()> {
    let relative = output
        .strip_prefix(destination)
        .expect("extraction output is rooted");
    root.create_dir_all(relative).map_err(|source| Error::Io {
        operation: "create extracted directory".to_owned(),
        path: output.to_owned(),
        source,
    })
}

pub fn write_extracted_file<R: Read>(
    reader: &mut R,
    declared_size: u64,
    root: &TrustedDir,
    destination: &Path,
    output: &Path,
    archive: &Path,
) -> Result<()> {
    let relative = output
        .strip_prefix(destination)
        .expect("extraction output is rooted");
    let mut file = root.create_new_file(relative).map_err(|source| Error::Io {
        operation: "create extracted file".to_owned(),
        path: output.to_owned(),
        source,
    })?;
    let copied =
        io::copy(&mut reader.take(declared_size), &mut file).map_err(|source| Error::Io {
            operation: "write extracted file".to_owned(),
            path: output.to_owned(),
            source,
        })?;
    if copied != declared_size {
        return Err(Error::Extraction {
            archive: archive.to_owned(),
            message: format!(
                "extracted file {} has {} bytes, expected {}",
                output.strip_prefix(destination).unwrap_or(output).display(),
                copied,
                declared_size
            ),
        });
    }
    file.flush().map_err(|source| Error::Io {
        operation: "flush extracted file".to_owned(),
        path: output.to_owned(),
        source,
    })
}

pub fn open_extraction_root(destination: &Path) -> Result<TrustedDir> {
    TrustedDir::open(destination).map_err(|source| Error::Io {
        operation: "open extraction root".to_owned(),
        path: destination.to_owned(),
        source,
    })
}
