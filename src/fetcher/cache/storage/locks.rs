use std::{
    ffi::OsString,
    fs::{self, File},
    path::{Path, PathBuf},
    sync::Arc,
};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use crate::{
    error::{Error, Result},
    fetcher::filesystem::TrustedDir,
};

use super::{super::Acquisition, files::is_unsafe_cache_open_error};

pub(super) const LIFECYCLE_LOCK: &str = "lifecycle.lock";
const LOCK_DIRECTORY_SUFFIX: &str = ".locks";

pub(in crate::fetcher) struct CacheLock {
    file: File,
}

#[derive(Clone, Copy)]
pub(super) enum LockMode {
    Shared,
    Exclusive,
}

impl Drop for CacheLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}
pub(in crate::fetcher::cache) fn lock_directory_path(cache: &Path) -> PathBuf {
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

pub(in crate::fetcher::cache) fn open_lock_directory(cache: &Path) -> Result<Arc<TrustedDir>> {
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

pub(in crate::fetcher::cache) fn lock_entry(acquisition: &Acquisition) -> Result<CacheLock> {
    lock_entry_with_mode(acquisition, LockMode::Exclusive)
}

pub(in crate::fetcher::cache) fn lock_entry_shared(acquisition: &Acquisition) -> Result<CacheLock> {
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

pub(in crate::fetcher::cache) fn lock_child_file(
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

pub(in crate::fetcher::cache) fn validate_cache_directory(
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
