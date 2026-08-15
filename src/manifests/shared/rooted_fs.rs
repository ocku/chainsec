use std::{
    cell::RefCell,
    fs::{self, File, OpenOptions},
    io::{self, Read},
    path::{Component, Path, PathBuf},
};

#[cfg(unix)]
use std::{
    ffi::CString,
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    },
};

use crate::{
    error::{Error, Result},
    model::DEFAULT_MAX_MANIFEST_FILE_SIZE,
};

/// Maximum bytes accepted from any declaration, workspace manifest, import map, or lockfile.
///
/// Manifest parsers share this boundary so no ecosystem can accidentally accept larger untrusted
/// parser inputs than another. This is intentionally independent of source and archive limits.
pub(in crate::manifests) const MAX_MANIFEST_FILE_BYTES: u64 = DEFAULT_MAX_MANIFEST_FILE_SIZE;

thread_local! {
    static ACTIVE_MANIFEST_FILE_LIMITS: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
    static ACTIVE_ROOTS: RefCell<Vec<ActiveRoot>> = const { RefCell::new(Vec::new()) };
}

struct ActiveRoot {
    path: PathBuf,
    directory: File,
}

/// An opened manifest directory used as the authority for all paths beneath it.
///
/// Keeping this descriptor open makes later checks and reads independent of replacement of the
/// root path or any of its parent path components.
pub(in crate::manifests) struct ManifestRoot {
    path: PathBuf,
    directory: File,
}

impl ManifestRoot {
    pub(in crate::manifests) fn open(path: &Path) -> Result<Self> {
        let path = absolute_lexical(path).map_err(|source| io_error(path, source))?;
        let directory = open_directory(&path)?;
        Ok(Self { path, directory })
    }

    pub(in crate::manifests) fn path(&self) -> &Path {
        &self.path
    }

    pub(in crate::manifests) fn is_file(&self, relative: &Path) -> Result<bool> {
        is_open_file(self.open_relative(relative), &self.path.join(relative))
    }

    fn open_relative(&self, relative: &Path) -> Result<File> {
        open_beneath(&self.directory, &self.path, relative)
    }
}

pub(in crate::manifests) fn is_file_beneath(directory: &Path, relative: &Path) -> Result<bool> {
    let directory = absolute_lexical(directory).map_err(|source| io_error(directory, source))?;
    let rooted = ACTIVE_ROOTS.with(|roots| {
        roots
            .borrow()
            .iter()
            .find(|root| root.path == directory)
            .map(|root| open_beneath(&root.directory, &root.path, relative))
    });
    match rooted {
        Some(file) => is_open_file(file, &directory.join(relative)),
        None => ManifestRoot::open(&directory)?.is_file(relative),
    }
}

fn is_open_file(file: Result<File>, path: &Path) -> Result<bool> {
    match file {
        Ok(file) => file
            .metadata()
            .map(|metadata| metadata.file_type().is_file())
            .map_err(|source| io_error(path, source)),
        Err(Error::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
pub(super) fn clone_root_directory(directory: &Path) -> Result<(PathBuf, File)> {
    let directory = absolute_lexical(directory).map_err(|source| io_error(directory, source))?;
    let rooted = ACTIVE_ROOTS.with(|roots| {
        roots
            .borrow()
            .iter()
            .find(|root| root.path == directory)
            .map(|root| {
                root.directory
                    .try_clone()
                    .map_err(|source| io_error(&directory, source))
            })
    });
    let descriptor = match rooted {
        Some(descriptor) => descriptor?,
        None => ManifestRoot::open(&directory)?.directory,
    };
    Ok((directory, descriptor))
}

#[cfg(test)]
pub(in crate::manifests) fn with_manifest_roots<T>(
    roots: &[ManifestRoot],
    operation: impl FnOnce() -> T,
) -> Result<T> {
    with_manifest_roots_and_limit(roots, MAX_MANIFEST_FILE_BYTES, operation)
}

pub(in crate::manifests) fn with_manifest_roots_and_limit<T>(
    roots: &[ManifestRoot],
    max_manifest_file_size: u64,
    operation: impl FnOnce() -> T,
) -> Result<T> {
    let active = roots
        .iter()
        .map(|root| {
            Ok(ActiveRoot {
                path: root.path.clone(),
                directory: root
                    .directory
                    .try_clone()
                    .map_err(|source| io_error(&root.path, source))?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let previous_len = ACTIVE_ROOTS.with(|roots| {
        let mut roots = roots.borrow_mut();
        let previous_len = roots.len();
        roots.extend(active);
        previous_len
    });
    let guard = ActiveRootsGuard(previous_len);
    ACTIVE_MANIFEST_FILE_LIMITS.with(|limits| limits.borrow_mut().push(max_manifest_file_size));
    let limit_guard = ActiveManifestFileLimitGuard;
    let result = operation();
    drop(limit_guard);
    drop(guard);
    Ok(result)
}

struct ActiveManifestFileLimitGuard;

impl Drop for ActiveManifestFileLimitGuard {
    fn drop(&mut self) {
        ACTIVE_MANIFEST_FILE_LIMITS.with(|limits| {
            limits.borrow_mut().pop();
        });
    }
}

struct ActiveRootsGuard(usize);

impl Drop for ActiveRootsGuard {
    fn drop(&mut self) {
        ACTIVE_ROOTS.with(|roots| roots.borrow_mut().truncate(self.0));
    }
}

pub(in crate::manifests) fn read(path: &Path) -> Result<String> {
    let absolute = absolute_lexical(path).map_err(|source| io_error(path, source))?;
    let rooted = ACTIVE_ROOTS.with(|roots| {
        roots
            .borrow()
            .iter()
            .filter_map(|root| {
                absolute
                    .strip_prefix(&root.path)
                    .ok()
                    .map(|relative| (root.path.components().count(), root, relative.to_owned()))
            })
            .max_by_key(|(depth, _, _)| *depth)
            .map(|(_, root, relative)| open_beneath(&root.directory, &root.path, &relative))
    });
    if let Some(file) = rooted {
        return read_open_file(path, file?);
    }
    if ACTIVE_ROOTS.with(|roots| !roots.borrow().is_empty()) {
        return Err(manifest_error(
            path,
            "manifest path is outside the active discovery root",
        ));
    }

    reject_symlink(path)?;
    let file = open_file(path)?;
    read_open_file(path, file)
}

#[cfg(unix)]
pub(in crate::manifests) fn read_beneath(directory: &Path, relative: &Path) -> Result<String> {
    let directory = absolute_lexical(directory).map_err(|source| io_error(directory, source))?;
    let rooted = ACTIVE_ROOTS.with(|roots| {
        roots
            .borrow()
            .iter()
            .find(|root| root.path == directory)
            .map(|root| open_beneath(&root.directory, &root.path, relative))
    });
    if let Some(file) = rooted {
        return read_open_file(&directory.join(relative), file?);
    }

    let root = ManifestRoot::open(&directory)?;
    let path = root.path.join(relative);
    read_open_file(&path, root.open_relative(relative)?)
}

#[cfg(not(unix))]
pub(in crate::manifests) fn read_beneath(directory: &Path, relative: &Path) -> Result<String> {
    Err(manifest_error(
        &directory.join(relative),
        "safe manifest reads are unsupported on this platform",
    ))
}

fn read_open_file(path: &Path, mut file: File) -> Result<String> {
    let limit = ACTIVE_MANIFEST_FILE_LIMITS.with(|limits| {
        limits
            .borrow()
            .last()
            .copied()
            .unwrap_or(MAX_MANIFEST_FILE_BYTES)
    });
    let metadata = file.metadata().map_err(|source| io_error(path, source))?;
    if !metadata.file_type().is_file() {
        return Err(manifest_error(path, "manifest is not a regular file"));
    }
    if metadata.len() > limit {
        return Err(manifest_file_limit_error(path, limit));
    }

    // The descriptor may refer to a concurrently growing file. `take` ensures the allocation and
    // read remain bounded even when the size observed above becomes stale.
    let capacity = usize::try_from(metadata.len().min(limit)).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(path, source))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(manifest_file_limit_error(path, limit));
    }
    String::from_utf8(bytes).map_err(|source| {
        io_error(
            path,
            io::Error::new(io::ErrorKind::InvalidData, source.utf8_error()),
        )
    })
}

fn reject_symlink(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if metadata.file_type().is_symlink() {
        return Err(manifest_error(path, "refusing to read a symbolic link"));
    }
    Ok(())
}

fn absolute_lexical(path: &Path) -> io::Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(component) => normalized.push(component),
        }
    }
    Ok(normalized)
}

#[cfg(unix)]
fn open_directory(path: &Path) -> Result<File> {
    // macOS exposes `/var` and `/tmp` as symlinks, so a lexical component-by-
    // component `O_NOFOLLOW` walk rejects otherwise valid absolute directories
    // (for example every `tempfile::tempdir()` under `/var/folders/.../T`).
    // Resolve only the first path component (a root-owned top-level directory)
    // and then walk the remainder with `O_NOFOLLOW`, preserving rejection of
    // any attacker-controllable intermediate symlink deeper in the path.
    let resolved = resolve_root_symlink(path).map_err(|source| io_error(path, source))?;
    open_directory_no_follow(&resolved, path)
}

#[cfg(unix)]
fn open_directory_no_follow(path: &Path, original: &Path) -> Result<File> {
    let mut directory = open_at(
        libc::AT_FDCWD,
        Path::new("/"),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NONBLOCK,
    )
    .map_err(|source| io_error(original, source))?;

    // `O_NOFOLLOW` protects only the final component passed to `open`. Traverse
    // from the filesystem root with descriptor-relative opens so no ancestor can
    // redirect the resolved root.
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                directory = open_at(
                    directory.as_raw_fd(),
                    Path::new(name),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                )
                .map_err(|source| io_error(original, source))?;
            }
            Component::ParentDir | Component::Prefix(_) => {
                return Err(manifest_error(
                    original,
                    "manifest root must be an absolute directory",
                ));
            }
        }
    }
    Ok(directory)
}

/// Resolves only the first normal component of an absolute path through
/// `fs::canonicalize`.
///
/// The first component of an absolute path is a top-level directory owned by
/// root, so following its symlink cannot be influenced by an untrusted party.
/// This is what makes macOS temp directories (`/var/folders/.../T`, `/tmp/...`)
/// usable while every deeper component is still checked with `O_NOFOLLOW`.
#[cfg(unix)]
fn resolve_root_symlink(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        return Ok(path.to_owned());
    }
    let mut components = path.components().filter_map(|component| match component {
        Component::Normal(name) => Some(name.to_os_string()),
        _ => None,
    });
    let Some(first) = components.next() else {
        return Ok(path.to_owned());
    };
    let mut resolved = std::fs::canonicalize(Path::new("/").join(&first))?;
    for remaining in components {
        resolved.push(remaining);
    }
    Ok(resolved)
}

#[cfg(not(unix))]
fn open_directory(path: &Path) -> Result<File> {
    Err(manifest_error(
        path,
        "safe manifest reads are unsupported on this platform",
    ))
}

#[cfg(unix)]
fn open_beneath(directory: &File, root: &Path, relative: &Path) -> Result<File> {
    let mut current = directory
        .try_clone()
        .map_err(|source| io_error(root, source))?;
    let components = relative.components().collect::<Vec<_>>();
    if components.is_empty() {
        return Err(manifest_error(root, "manifest path does not name a file"));
    }
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::CurDir => {}
            Component::Normal(name) => {
                let directory_component = index + 1 < components.len();
                let flags = libc::O_RDONLY
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | if directory_component {
                        libc::O_DIRECTORY
                    } else {
                        0
                    };
                current = open_at(current.as_raw_fd(), Path::new(name), flags)
                    .map_err(|source| io_error(&root.join(relative), source))?;
            }
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(manifest_error(
                    &root.join(relative),
                    "manifest path must remain within its discovery root",
                ));
            }
        }
    }
    Ok(current)
}

#[cfg(not(unix))]
fn open_beneath(_directory: &File, root: &Path, relative: &Path) -> Result<File> {
    Err(manifest_error(
        &root.join(relative),
        "safe manifest reads are unsupported on this platform",
    ))
}

#[cfg(unix)]
fn open_file(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|source| io_error(path, source))
}

#[cfg(unix)]
pub(super) fn open_at(directory: RawFd, path: &Path, flags: i32) -> io::Result<File> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // SAFETY: `path` is NUL terminated and the returned descriptor is uniquely owned here.
    let descriptor = unsafe { libc::openat(directory, path.as_ptr(), flags | libc::O_CLOEXEC) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `descriptor` was returned by `openat` and ownership is transferred to `File`.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(not(unix))]
fn open_file(path: &Path) -> Result<File> {
    Err(manifest_error(
        path,
        "safe manifest reads are unsupported on this platform",
    ))
}

pub(super) fn io_error(path: &Path, source: io::Error) -> Error {
    Error::Io {
        operation: "read".to_owned(),
        path: path.to_owned(),
        source,
    }
}

fn manifest_file_limit_error(path: &Path, limit: u64) -> Error {
    manifest_error(
        path,
        format!("manifest exceeds the shared {limit}-byte file limit"),
    )
}

pub(in crate::manifests) fn manifest_error(path: &Path, error: impl ToString) -> Error {
    Error::Manifest {
        path: path.to_owned(),
        message: error.to_string(),
    }
}
