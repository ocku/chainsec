use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{self, Cursor, Read, Write},
    path::{Component, Path, PathBuf},
};

use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use tar::Archive;
use xz2::read::XzDecoder;
use zip::ZipArchive;

use crate::{
    error::{Error, Result},
    model::EngineLimits,
};

#[derive(Debug, Default)]
pub(super) struct ExtractionStats {
    pub(super) files: u64,
    pub(super) bytes: u64,
}

pub(super) fn safe_relative(path: &Path) -> bool {
    !path.is_absolute()
        && path.components().count() <= 128
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

pub(super) fn check_extraction_limits(
    stats: &ExtractionStats,
    limits: &EngineLimits,
) -> Result<()> {
    if stats.files > limits.max_extracted_files {
        return Err(Error::LimitExceeded {
            resource: "extracted files".to_owned(),
            limit: limits.max_extracted_files,
        });
    }
    if stats.bytes > limits.max_extracted_bytes {
        return Err(Error::LimitExceeded {
            resource: "extracted bytes".to_owned(),
            limit: limits.max_extracted_bytes,
        });
    }
    Ok(())
}

pub(super) fn extract(
    bytes: &[u8],
    name: &str,
    destination: &Path,
    limits: &EngineLimits,
) -> Result<ExtractionStats> {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".whl") || lower.ends_with(".zip") {
        extract_zip(bytes, destination, limits)
    } else if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        extract_tar(
            GzDecoder::new(Cursor::new(bytes)),
            name,
            destination,
            limits,
        )
    } else if lower.ends_with(".tar.bz2") {
        extract_tar(
            BzDecoder::new(Cursor::new(bytes)),
            name,
            destination,
            limits,
        )
    } else if lower.ends_with(".tar.xz") {
        extract_tar(
            XzDecoder::new(Cursor::new(bytes)),
            name,
            destination,
            limits,
        )
    } else if lower.ends_with(".tar") {
        extract_tar(Cursor::new(bytes), name, destination, limits)
    } else {
        Err(Error::Extraction {
            archive: PathBuf::from(name),
            message: "unsupported archive format".to_owned(),
        })
    }
}

fn reject_symlink_components(
    destination: &Path,
    output: &Path,
    archive: &Path,
    context: &str,
) -> Result<()> {
    let relative = output
        .strip_prefix(destination)
        .map_err(|_| Error::Extraction {
            archive: archive.to_owned(),
            message: format!(
                "extracted path {} is outside destination {}",
                output.display(),
                destination.display()
            ),
        })?;
    let mut current = destination.to_owned();
    match fs::symlink_metadata(&current) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(Error::Extraction {
                archive: archive.to_owned(),
                message: format!("symlinked extraction root {}", current.display()),
            });
        }
        Ok(_) => {}
        Err(source) => {
            return Err(Error::Io {
                operation: context.to_owned(),
                path: current,
                source,
            });
        }
    }

    for component in relative.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Error::Extraction {
                    archive: archive.to_owned(),
                    message: format!("symlink in extracted path {}", current.display()),
                });
            }
            Ok(_) => {}
            Err(source) if source.kind() == io::ErrorKind::NotFound => break,
            Err(source) => {
                return Err(Error::Io {
                    operation: context.to_owned(),
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(())
}

fn create_extracted_file(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

fn reject_duplicate_path(seen: &mut HashSet<PathBuf>, path: &Path, archive: &Path) -> Result<()> {
    if seen.insert(path.to_owned()) {
        return Ok(());
    }

    Err(Error::Extraction {
        archive: archive.to_owned(),
        message: format!("duplicate path {}", path.display()),
    })
}

fn create_extracted_directory(destination: &Path, output: &Path, archive: &Path) -> Result<()> {
    reject_symlink_components(destination, output, archive, "inspect extracted directory")?;
    fs::create_dir_all(output).map_err(|source| Error::Io {
        operation: "create extracted directory".to_owned(),
        path: output.to_owned(),
        source,
    })?;
    reject_symlink_components(destination, output, archive, "inspect extracted directory")
}

fn write_extracted_file<R: Read>(
    reader: &mut R,
    declared_size: u64,
    destination: &Path,
    output: &Path,
    archive: &Path,
    stats: &mut ExtractionStats,
    limits: &EngineLimits,
) -> Result<()> {
    stats.files += 1;
    stats.bytes = stats.bytes.saturating_add(declared_size);
    check_extraction_limits(stats, limits)?;

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|source| Error::Io {
            operation: "create extracted parent".to_owned(),
            path: parent.to_owned(),
            source,
        })?;
    }
    reject_symlink_components(destination, output, archive, "inspect extracted path")?;

    let mut file = create_extracted_file(output).map_err(|source| Error::Io {
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

fn extract_tar<R: Read>(
    reader: R,
    name: &str,
    destination: &Path,
    limits: &EngineLimits,
) -> Result<ExtractionStats> {
    let mut archive = Archive::new(reader);
    let mut stats = ExtractionStats::default();
    let mut seen = HashSet::new();
    let entries = archive.entries().map_err(|error| Error::Extraction {
        archive: PathBuf::from(name),
        message: error.to_string(),
    })?;
    for entry in entries {
        let mut entry = entry.map_err(|error| Error::Extraction {
            archive: PathBuf::from(name),
            message: error.to_string(),
        })?;
        let kind = entry.header().entry_type();
        if kind.is_pax_global_extensions() || kind.is_pax_local_extensions() {
            continue;
        }

        let path = entry
            .path()
            .map_err(|error| Error::Extraction {
                archive: PathBuf::from(name),
                message: error.to_string(),
            })?
            .into_owned();
        if !safe_relative(&path) {
            return Err(Error::Extraction {
                archive: PathBuf::from(name),
                message: format!("unsafe or excessively deep path {}", path.display()),
            });
        }
        reject_duplicate_path(&mut seen, &path, Path::new(name))?;

        if kind.is_symlink() || kind.is_hard_link() || !(kind.is_file() || kind.is_dir()) {
            return Err(Error::Extraction {
                archive: PathBuf::from(name),
                message: format!("special file rejected: {}", path.display()),
            });
        }
        let output = destination.join(&path);
        if kind.is_dir() {
            create_extracted_directory(destination, &output, Path::new(name))?;
            continue;
        }
        let entry_size = entry.size();
        write_extracted_file(
            &mut entry,
            entry_size,
            destination,
            &output,
            Path::new(name),
            &mut stats,
            limits,
        )?;
    }
    Ok(stats)
}

fn extract_zip(bytes: &[u8], destination: &Path, limits: &EngineLimits) -> Result<ExtractionStats> {
    let mut archive = ZipArchive::new(Cursor::new(bytes)).map_err(|error| Error::Extraction {
        archive: PathBuf::from("zip"),
        message: error.to_string(),
    })?;
    let mut stats = ExtractionStats::default();
    let mut seen = HashSet::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|error| Error::Extraction {
            archive: PathBuf::from("zip"),
            message: error.to_string(),
        })?;
        let path = entry
            .enclosed_name()
            .ok_or_else(|| Error::Extraction {
                archive: PathBuf::from("zip"),
                message: format!("unsafe path {}", entry.name()),
            })?
            .to_owned();
        reject_duplicate_path(&mut seen, &path, Path::new("zip"))?;

        if let Some(mode) = entry.unix_mode() {
            match mode & 0o170000 {
                0 | 0o040000 | 0o100000 => {}
                0o120000 => {
                    return Err(Error::Extraction {
                        archive: PathBuf::from("zip"),
                        message: format!("symlink rejected: {}", path.display()),
                    });
                }
                _ => {
                    return Err(Error::Extraction {
                        archive: PathBuf::from("zip"),
                        message: format!("special file rejected: {}", path.display()),
                    });
                }
            }
        }
        let output = destination.join(&path);
        if entry.is_dir() {
            create_extracted_directory(destination, &output, Path::new("zip"))?;
            continue;
        }
        let entry_size = entry.size();
        write_extracted_file(
            &mut entry,
            entry_size,
            destination,
            &output,
            Path::new("zip"),
            &mut stats,
            limits,
        )?;
    }
    Ok(stats)
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
