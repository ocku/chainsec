use std::{
    ffi::OsString,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use crate::{
    error::{Error, Result},
    fetcher::filesystem::TrustedDir,
    model::EngineLimits,
};

use super::{Acquisition, CACHED_ARTIFACT};

const LIFECYCLE_LOCK: &str = "lifecycle.lock";
const LOCK_DIRECTORY_SUFFIX: &str = ".locks";

pub(in crate::fetcher) struct CacheLock {
    file: File,
}

#[derive(Clone, Copy)]
enum LockMode {
    Shared,
    Exclusive,
}

impl Drop for CacheLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn normalize_cache(cache: &Path) -> Result<PathBuf> {
    let parent = cache
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|source| Error::Io {
        operation: "create cache parent directory".to_owned(),
        path: parent.to_owned(),
        source,
    })?;
    let parent = fs::canonicalize(parent).map_err(|source| Error::Io {
        operation: "canonicalize cache parent directory".to_owned(),
        path: parent.to_owned(),
        source,
    })?;
    let name = cache
        .file_name()
        .filter(|name| *name != "." && *name != "..")
        .ok_or_else(|| Error::InvalidConfiguration {
            message: format!("cache path must name a directory: {}", cache.display()),
        })?;
    Ok(parent.join(name))
}

fn ensure_real_directory(path: &Path, operation: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(Error::Policy {
                operation: "cache confinement".to_owned(),
                message: format!("cache path is not a regular directory: {}", path.display()),
            })
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => match fs::create_dir(path) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                ensure_real_directory(path, operation)
            }
            Err(source) => Err(Error::Io {
                operation: operation.to_owned(),
                path: path.to_owned(),
                source,
            }),
        },
        Err(source) => Err(Error::Io {
            operation: format!("inspect {operation}"),
            path: path.to_owned(),
            source,
        }),
    }
}

pub(in crate::fetcher) fn prepare_cache(
    cache: &Path,
) -> Result<(PathBuf, TrustedDir, Arc<TrustedDir>, PathBuf, CacheLock)> {
    let cache = normalize_cache(cache)?;
    let lock_directory = lock_directory_path(&cache);
    let locks = open_lock_directory(&cache)?;
    ensure_real_directory(&cache, "create cache directory")?;
    // Another initializer may transiently replace the just-created directory
    // while converging on the same cache path. Re-open once; the successful
    // root and its lifecycle lock are retained together thereafter.
    for _ in 0..2 {
        let root = TrustedDir::open(&cache).map_err(|source| Error::Io {
            operation: "open cache directory".to_owned(),
            path: cache.clone(),
            source,
        })?;
        validate_cache_directory(&root, &cache, "cache root")?;
        match lock_lifecycle(&locks, &cache, LockMode::Shared) {
            Ok(lock) => return Ok((cache, root, locks, lock_directory, lock)),
            Err(Error::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
                ensure_real_directory(&cache, "recreate cache directory")?;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("cache initialization retry loop always returns")
}

pub(in crate::fetcher) fn purge_cache(cache: &Path) -> Result<bool> {
    match fs::symlink_metadata(cache) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(Error::Policy {
                operation: "cache purge".to_owned(),
                message: format!("cache path is not a regular directory: {}", cache.display()),
            });
        }
        Ok(_) => {}
        Err(source) => {
            return Err(Error::Io {
                operation: "inspect cache directory".to_owned(),
                path: cache.to_owned(),
                source,
            });
        }
    }
    let cache = normalize_cache(cache)?;
    let locks = open_lock_directory(&cache)?;
    let root = TrustedDir::open(&cache).map_err(|source| Error::Io {
        operation: "open cache directory for purge".to_owned(),
        path: cache.clone(),
        source,
    })?;
    validate_cache_directory(&root, &cache, "cache root")?;
    let _lifecycle_lock = lock_lifecycle(&locks, &cache, LockMode::Exclusive)?;
    purge_stale_entry_locks(&locks, &lock_directory_path(&cache))?;
    for name in root.list_child_names().map_err(|source| Error::Io {
        operation: "read cache directory for purge".to_owned(),
        path: cache.clone(),
        source,
    })? {
        let path = cache.join(&name);
        root.remove_child_all(&name).map_err(|source| Error::Io {
            operation: "remove cache content during purge".to_owned(),
            path,
            source,
        })?;
    }
    Ok(true)
}

fn purge_stale_entry_locks(locks: &TrustedDir, lock_directory: &Path) -> Result<()> {
    for name in locks.list_child_names().map_err(|source| Error::Io {
        operation: "read cache lock directory".to_owned(),
        path: lock_directory.to_owned(),
        source,
    })? {
        if name == Path::new(LIFECYCLE_LOCK) || !is_entry_lock_name(&name) {
            continue;
        }
        locks.remove_child_all(&name).map_err(|source| Error::Io {
            operation: "remove stale cache entry lock".to_owned(),
            path: lock_directory.join(&name),
            source,
        })?;
    }
    Ok(())
}

fn is_entry_lock_name(name: &Path) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(identity) = name.strip_suffix(".lock") else {
        return false;
    };
    identity.len() == 64 && identity.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn lock_lifecycle(locks: &TrustedDir, cache: &Path, mode: LockMode) -> Result<CacheLock> {
    lock_child_file(
        locks,
        Path::new(LIFECYCLE_LOCK),
        &lock_directory_path(cache).join(LIFECYCLE_LOCK),
        "cache lifecycle",
        mode,
    )
}

fn lock_directory_path(cache: &Path) -> PathBuf {
    let mut name = OsString::from(
        cache
            .file_name()
            .expect("normalized cache path always has a file name"),
    );
    name.push(LOCK_DIRECTORY_SUFFIX);
    cache
        .parent()
        .expect("normalized cache path has a parent")
        .join(name)
}

fn open_lock_directory(cache: &Path) -> Result<Arc<TrustedDir>> {
    let path = lock_directory_path(cache);
    let parent = cache.parent().expect("normalized cache path has a parent");
    let parent = TrustedDir::open(parent).map_err(|source| Error::Io {
        operation: "open cache lock parent directory".to_owned(),
        path: parent.to_owned(),
        source,
    })?;
    let name = path
        .file_name()
        .expect("lock directory path has a file name");
    let directory = parent
        .open_or_create_child_dir(Path::new(name))
        .map_err(|source| Error::Io {
            operation: "create cache lock directory".to_owned(),
            path: path.clone(),
            source,
        })?;
    validate_lock_directory(&directory, &path)?;
    Ok(Arc::new(directory))
}

pub(super) fn lock_entry(acquisition: &Acquisition) -> Result<CacheLock> {
    lock_entry_with_mode(acquisition, LockMode::Exclusive)
}

pub(super) fn lock_entry_shared(acquisition: &Acquisition) -> Result<CacheLock> {
    lock_entry_with_mode(acquisition, LockMode::Shared)
}

fn lock_entry_with_mode(acquisition: &Acquisition, mode: LockMode) -> Result<CacheLock> {
    lock_child_file(
        &acquisition.locks,
        Path::new(&format!("{}.lock", acquisition.identity)),
        &acquisition
            .lock_directory
            .join(format!("{}.lock", acquisition.identity)),
        "cache entry",
        mode,
    )
}

fn lock_child_file(
    directory: &TrustedDir,
    name: &Path,
    path: &Path,
    operation: &str,
    mode: LockMode,
) -> Result<CacheLock> {
    let file = directory
        .open_or_create_child_file(name)
        .map_err(|source| {
            if is_unsafe_cache_open_error(&source) {
                Error::Policy {
                    operation: "cache confinement".to_owned(),
                    message: format!("{operation} lock is not a regular file: {}", path.display()),
                }
            } else {
                Error::Io {
                    operation: format!("open {operation} lock"),
                    path: path.to_owned(),
                    source,
                }
            }
        })?;
    let metadata = file.metadata().map_err(|source| Error::Io {
        operation: format!("inspect opened {operation} lock"),
        path: path.to_owned(),
        source,
    })?;
    validate_lock_file(&metadata, path, operation)?;
    let result = match mode {
        LockMode::Shared => file.lock_shared(),
        LockMode::Exclusive => file.lock(),
    };
    result.map_err(|source| Error::Io {
        operation: format!("lock {operation}"),
        path: path.to_owned(),
        source,
    })?;
    Ok(CacheLock { file })
}

pub(super) fn validate_cache_directory(
    directory: &TrustedDir,
    path: &Path,
    description: &str,
) -> Result<()> {
    #[cfg(unix)]
    {
        let metadata = directory.metadata().map_err(|source| Error::Io {
            operation: format!("inspect {description}"),
            path: path.to_owned(),
            source,
        })?;
        // SAFETY: `geteuid` has no preconditions and does not mutate process state.
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid || metadata.mode() & 0o022 != 0 {
            return Err(Error::Policy {
                operation: "cache confinement".to_owned(),
                message: format!(
                    "{description} must be owned by the effective user and not be group- or world-writable: {}",
                    path.display()
                ),
            });
        }
    }
    Ok(())
}

fn validate_lock_directory(directory: &TrustedDir, path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let metadata = directory.metadata().map_err(|source| Error::Io {
            operation: "inspect cache lock directory".to_owned(),
            path: path.to_owned(),
            source,
        })?;
        // SAFETY: `geteuid` has no preconditions and does not mutate process state.
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid || metadata.mode() & 0o077 != 0 {
            return Err(Error::Policy {
                operation: "cache confinement".to_owned(),
                message: format!(
                    "cache lock directory must be owned by the effective user and have mode 0700: {}",
                    path.display()
                ),
            });
        }
    }
    Ok(())
}

fn validate_lock_file(metadata: &fs::Metadata, path: &Path, operation: &str) -> Result<()> {
    if !metadata.is_file() {
        return Err(Error::Policy {
            operation: "cache confinement".to_owned(),
            message: format!("{operation} lock is not a regular file: {}", path.display()),
        });
    }
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` has no preconditions and does not mutate process state.
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid || metadata.mode() & 0o077 != 0 || metadata.nlink() != 1
        {
            return Err(Error::Policy {
                operation: "cache confinement".to_owned(),
                message: format!(
                    "{operation} lock must be owner-only, owned by the effective user, and have one link: {}",
                    path.display()
                ),
            });
        }
    }
    Ok(())
}

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

pub(super) fn read_bounded_regular_file(
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

pub(super) fn write_child_file(
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

pub(super) fn copy_cache_payload(
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
        limits.max_archive_bytes,
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
                stats.files = stats.files.saturating_add(1);
                check_publication_count(stats.files, limits.max_extracted_files)?;
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
                let remaining = limits.max_extracted_bytes.saturating_sub(stats.bytes);
                let copied = copy_opened_regular_file(
                    file,
                    &entry_path,
                    destination,
                    &relative,
                    &destination_path.join(&relative),
                    limits.max_source_file_bytes.min(remaining),
                    if remaining < limits.max_source_file_bytes {
                        "extracted bytes"
                    } else {
                        "source file bytes"
                    },
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
