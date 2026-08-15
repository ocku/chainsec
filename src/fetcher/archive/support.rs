use std::{
    collections::{HashMap, hash_map::Entry},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

use crate::{
    error::{Error, Result},
    fetcher::{budget::AcquisitionDeadline, filesystem::TrustedDir},
    model::EngineLimits,
};

#[derive(Debug, Default)]
pub struct ExtractionStats {
    pub files: u64,
    pub bytes: u64,
}

pub fn safe_relative(path: &Path, max_file_depth: usize) -> bool {
    normalize_relative(path, max_file_depth).is_some()
}

pub fn normalize_relative(path: &Path, max_file_depth: usize) -> Option<PathBuf> {
    if path.is_absolute() {
        return None;
    }

    let mut normalized = PathBuf::new();
    let mut depth = 0;
    for component in path.components() {
        match component {
            Component::Normal(component) if depth < max_file_depth => {
                normalized.push(component);
                depth += 1;
            }
            Component::CurDir => {}
            _ => return None,
        }
    }
    Some(normalized)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaterializedPathKind {
    File,
    Directory,
}

impl MaterializedPathKind {
    fn name(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
        }
    }
}

#[derive(Debug)]
struct MaterializedPath {
    kind: MaterializedPathKind,
    explicit: bool,
}

#[derive(Debug, Default)]
pub struct MaterializedPaths {
    paths: HashMap<PathBuf, MaterializedPath>,
}

impl MaterializedPaths {
    pub fn account(
        &mut self,
        stats: &mut ExtractionStats,
        path: &Path,
        kind: MaterializedPathKind,
        limits: &EngineLimits,
        archive: &Path,
    ) -> Result<()> {
        let components = path.iter().collect::<Vec<_>>();
        let mut ancestor = PathBuf::new();
        for component in components.iter().take(components.len().saturating_sub(1)) {
            ancestor.push(component);
            self.account_directory(stats, &ancestor, false, limits, archive)?;
        }

        match kind {
            MaterializedPathKind::File => self.account_file(stats, path, limits, archive),
            MaterializedPathKind::Directory => {
                self.account_directory(stats, path, true, limits, archive)
            }
        }
    }

    fn account_file(
        &mut self,
        stats: &mut ExtractionStats,
        path: &Path,
        limits: &EngineLimits,
        archive: &Path,
    ) -> Result<()> {
        match self.paths.entry(path.to_owned()) {
            Entry::Vacant(entry) => {
                entry.insert(MaterializedPath {
                    kind: MaterializedPathKind::File,
                    explicit: true,
                });
                account_extracted_object(stats, limits)
            }
            Entry::Occupied(entry) if entry.get().kind == MaterializedPathKind::File => {
                Err(duplicate_path(path, archive))
            }
            Entry::Occupied(entry) => Err(path_type_conflict(
                path,
                MaterializedPathKind::File,
                entry.get().kind,
                archive,
            )),
        }
    }

    fn account_directory(
        &mut self,
        stats: &mut ExtractionStats,
        path: &Path,
        explicit: bool,
        limits: &EngineLimits,
        archive: &Path,
    ) -> Result<()> {
        match self.paths.entry(path.to_owned()) {
            Entry::Vacant(entry) => {
                entry.insert(MaterializedPath {
                    kind: MaterializedPathKind::Directory,
                    explicit,
                });
                account_extracted_object(stats, limits)
            }
            Entry::Occupied(mut entry) if entry.get().kind == MaterializedPathKind::Directory => {
                if explicit && entry.get().explicit {
                    return Err(duplicate_path(path, archive));
                }
                entry.get_mut().explicit |= explicit;
                Ok(())
            }
            Entry::Occupied(entry) => Err(path_type_conflict(
                path,
                MaterializedPathKind::Directory,
                entry.get().kind,
                archive,
            )),
        }
    }
}

fn duplicate_path(path: &Path, archive: &Path) -> Error {
    Error::Extraction {
        archive: archive.to_owned(),
        message: format!("duplicate path {}", path.display()),
    }
}

fn path_type_conflict(
    path: &Path,
    expected: MaterializedPathKind,
    actual: MaterializedPathKind,
    archive: &Path,
) -> Error {
    Error::Extraction {
        archive: archive.to_owned(),
        message: format!(
            "path type conflict at {}: expected {}, found {}",
            path.display(),
            expected.name(),
            actual.name()
        ),
    }
}

fn account_extracted_object(stats: &mut ExtractionStats, limits: &EngineLimits) -> Result<()> {
    stats.files = stats.files.saturating_add(1);
    check_extraction_limits(stats, limits)
}

pub fn account_extracted_entry(
    stats: &mut ExtractionStats,
    declared_size: u64,
    limits: &EngineLimits,
) -> Result<()> {
    account_extracted_object(stats, limits)?;
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
    deadline: &AcquisitionDeadline,
) -> Result<()> {
    deadline.check()?;
    let relative = output
        .strip_prefix(destination)
        .expect("extraction output is rooted");
    let mut file = root.create_new_file(relative).map_err(|source| Error::Io {
        operation: "create extracted file".to_owned(),
        path: output.to_owned(),
        source,
    })?;
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    while copied < declared_size {
        deadline.check()?;
        let remaining = declared_size - copied;
        let maximum = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let read = reader
            .read(&mut buffer[..maximum])
            .map_err(|source| Error::Io {
                operation: "read extracted file".to_owned(),
                path: output.to_owned(),
                source,
            })?;
        if read == 0 {
            break;
        }
        file.write_all(&buffer[..read])
            .map_err(|source| Error::Io {
                operation: "write extracted file".to_owned(),
                path: output.to_owned(),
                source,
            })?;
        copied += read as u64;
    }
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
    deadline.check()?;
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
