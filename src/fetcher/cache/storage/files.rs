use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

use crate::{
    error::{Error, Result},
    fetcher::filesystem::TrustedDir,
    model::EngineLimits,
};

use super::super::CACHED_ARTIFACT;

pub(in crate::fetcher) fn is_unsafe_cache_open_error(error: &std::io::Error) -> bool {
    if matches!(
        error.kind(),
        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::NotADirectory
    ) {
        return true;
    }
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(libc::ELOOP)
    }
    #[cfg(not(unix))]
    false
}

pub(in crate::fetcher::cache) fn read_bounded_regular_file(
    directory: &TrustedDir,
    relative: &Path,
    path: &Path,
    limit: u64,
) -> Result<Option<Vec<u8>>> {
    let file = match directory.open_file_no_follow(relative) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) if is_unsafe_cache_open_error(&error) => return Ok(None),
        Err(source) => {
            return Err(Error::Io {
                operation: "open cached file".to_owned(),
                path: path.to_owned(),
                source,
            });
        }
    };
    let metadata = file.metadata().map_err(|source| Error::Io {
        operation: "inspect opened cached file".to_owned(),
        path: path.to_owned(),
        source,
    })?;
    if !metadata.is_file() || metadata.len() > limit {
        return Ok(None);
    }
    let Some(capacity) = usize::try_from(metadata.len()).ok() else {
        return Ok(None);
    };
    let mut bytes = Vec::with_capacity(capacity);
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| Error::Io {
            operation: "read cached file".to_owned(),
            path: path.to_owned(),
            source,
        })?;
    Ok((bytes.len() as u64 <= limit).then_some(bytes))
}

pub(in crate::fetcher) fn write_cached_artifact(temporary: &Path, bytes: &[u8]) -> Result<()> {
    let path = temporary.join(CACHED_ARTIFACT);
    let root = TrustedDir::open(temporary).map_err(|source| Error::Io {
        operation: "open cache workspace".to_owned(),
        path: temporary.to_owned(),
        source,
    })?;
    write_child_file(
        &root,
        Path::new(CACHED_ARTIFACT),
        &path,
        bytes,
        "cached artifact",
    )
}

pub(in crate::fetcher::cache) fn write_child_file(
    directory: &TrustedDir,
    name: &Path,
    path: &Path,
    bytes: &[u8],
    description: &str,
) -> Result<()> {
    let mut file = directory
        .create_new_file(name)
        .map_err(|source| Error::Io {
            operation: format!("create {description}"),
            path: path.to_owned(),
            source,
        })?;
    file.write_all(bytes).map_err(|source| Error::Io {
        operation: format!("write {description}"),
        path: path.to_owned(),
        source,
    })
}

pub(in crate::fetcher::cache) fn copy_cache_payload(
    workspace: &Path,
    destination: &TrustedDir,
    destination_path: &Path,
    retain_source: bool,
    limits: &EngineLimits,
) -> Result<()> {
    let workspace_directory = TrustedDir::open(workspace).map_err(|source| Error::Io {
        operation: "open cache workspace for publication".to_owned(),
        path: workspace.to_owned(),
        source,
    })?;
    copy_regular_file_if_present(
        &workspace_directory,
        Path::new(CACHED_ARTIFACT),
        &workspace.join(CACHED_ARTIFACT),
        destination,
        destination_path,
        limits.max_archive_size,
    )?;
    if retain_source {
        let source_path = workspace.join("source");
        let source = workspace_directory
            .open_subdirectory(Path::new("source"))
            .map_err(|source| Error::Io {
                operation: "open cache source directory".to_owned(),
                path: source_path.clone(),
                source,
            })?;
        destination
            .create_dir_all(Path::new("source"))
            .map_err(|source| Error::Io {
                operation: "copy cache directory".to_owned(),
                path: destination_path.join("source"),
                source,
            })?;
        let mut stats = PublicationStats::default();
        copy_directory(
            &source,
            &source_path,
            Path::new("source"),
            destination,
            destination_path,
            limits,
            &mut stats,
        )?;
    }
    Ok(())
}

fn copy_regular_file_if_present(
    source_directory: &TrustedDir,
    relative: &Path,
    source_path: &Path,
    destination: &TrustedDir,
    destination_path: &Path,
    limit: u64,
) -> Result<()> {
    let file = match source_directory.open_file_no_follow(relative) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) if is_unsafe_cache_open_error(&error) => {
            return Err(unsafe_publication_entry(source_path, "cached artifact"));
        }
        Err(source) => {
            return Err(Error::Io {
                operation: "open cached artifact".to_owned(),
                path: source_path.to_owned(),
                source,
            });
        }
    };
    copy_opened_regular_file(
        file,
        source_path,
        destination,
        relative,
        &destination_path.join(relative),
        limit,
        "archive bytes",
        "cached artifact",
    )?;
    Ok(())
}

#[derive(Default)]
struct PublicationStats {
    files: u64,
    bytes: u64,
}

fn copy_directory(
    source: &TrustedDir,
    source_path: &Path,
    destination_relative: &Path,
    destination: &TrustedDir,
    destination_path: &Path,
    limits: &EngineLimits,
    stats: &mut PublicationStats,
) -> Result<()> {
    for name in source
        .list_child_names()
        .map_err(|source_error| Error::Io {
            operation: "read cache source directory".to_owned(),
            path: source_path.to_owned(),
            source: source_error,
        })?
    {
        let entry_path = source_path.join(&name);
        let relative = destination_relative.join(&name);
        match source.open_subdirectory(&name) {
            Ok(directory) => {
                destination
                    .create_dir_all(&relative)
                    .map_err(|source_error| Error::Io {
                        operation: "copy cache directory".to_owned(),
                        path: destination_path.join(&relative),
                        source: source_error,
                    })?;
                copy_directory(
                    &directory,
                    &entry_path,
                    &relative,
                    destination,
                    destination_path,
                    limits,
                    stats,
                )?;
            }
            Err(error) if is_not_directory_error(&error) => {
                let file = source.open_file_no_follow(&name).map_err(|source_error| {
                    if is_unsafe_cache_open_error(&source_error) {
                        unsafe_publication_entry(&entry_path, "cache source entry")
                    } else {
                        Error::Io {
                            operation: "open cache file".to_owned(),
                            path: entry_path.clone(),
                            source: source_error,
                        }
                    }
                })?;
                stats.files = stats.files.saturating_add(1);
                check_publication_count(stats.files, limits.max_extracted_files)?;
                let remaining = limits.max_extracted_size.saturating_sub(stats.bytes);
                let copied = copy_opened_regular_file(
                    file,
                    &entry_path,
                    destination,
                    &relative,
                    &destination_path.join(&relative),
                    remaining,
                    "extracted bytes",
                    "cache file",
                )?;
                stats.bytes = stats.bytes.saturating_add(copied);
            }
            Err(error) if is_unsafe_cache_open_error(&error) => {
                return Err(unsafe_publication_entry(&entry_path, "cache source entry"));
            }
            Err(source_error) => {
                return Err(Error::Io {
                    operation: "open cache source directory entry".to_owned(),
                    path: entry_path,
                    source: source_error,
                });
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn copy_opened_regular_file(
    mut source: File,
    source_path: &Path,
    destination: &TrustedDir,
    destination_relative: &Path,
    destination_path: &Path,
    limit: u64,
    limit_resource: &str,
    description: &str,
) -> Result<u64> {
    let metadata = source.metadata().map_err(|source_error| Error::Io {
        operation: format!("inspect opened {description}"),
        path: source_path.to_owned(),
        source: source_error,
    })?;
    if !metadata.is_file() {
        return Err(unsafe_publication_entry(source_path, description));
    }
    if metadata.len() > limit {
        return Err(Error::LimitExceeded {
            resource: limit_resource.to_owned(),
            limit,
        });
    }
    let mut destination_file =
        destination
            .create_new_file(destination_relative)
            .map_err(|source_error| Error::Io {
                operation: format!("create {description}"),
                path: destination_path.to_owned(),
                source: source_error,
            })?;
    let copied = std::io::copy(
        &mut (&mut source).take(limit.saturating_add(1)),
        &mut destination_file,
    )
    .map_err(|source_error| Error::Io {
        operation: format!("copy {description}"),
        path: source_path.to_owned(),
        source: source_error,
    })?;
    if copied > limit {
        return Err(Error::LimitExceeded {
            resource: limit_resource.to_owned(),
            limit,
        });
    }
    Ok(copied)
}

fn check_publication_count(files: u64, limit: u64) -> Result<()> {
    if files > limit {
        return Err(Error::LimitExceeded {
            resource: "extracted files".to_owned(),
            limit,
        });
    }
    Ok(())
}

fn unsafe_publication_entry(path: &Path, description: &str) -> Error {
    Error::Policy {
        operation: "cache publication".to_owned(),
        message: format!(
            "{description} is not a regular file or directory: {}",
            path.display()
        ),
    }
}

fn is_not_directory_error(error: &std::io::Error) -> bool {
    if error.kind() == std::io::ErrorKind::NotADirectory {
        return true;
    }
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(libc::ENOTDIR)
    }
    #[cfg(not(unix))]
    {
        error.kind() == std::io::ErrorKind::InvalidInput
    }
}
