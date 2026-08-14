use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{
    error::{Error, Result},
    fetcher::filesystem::TrustedDir,
};

use super::locks::{
    CacheLock, LIFECYCLE_LOCK, LockMode, lock_child_file, lock_directory_path, open_lock_directory,
    validate_cache_directory,
};

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
