use std::{
    cell::RefCell,
    fs::{self, File, OpenOptions},
    io::{self, Read},
    path::{Component, Path, PathBuf},
};

#[cfg(unix)]
use std::{
    ffi::{CStr, CString, OsStr},
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
        unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    },
};

use crate::error::{Error, Result};

const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

thread_local! {
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
pub(super) struct ManifestRoot {
    path: PathBuf,
    directory: File,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RootedFileType {
    Directory,
    File,
    Symlink,
    Other,
}

impl ManifestRoot {
    pub(super) fn open(path: &Path) -> Result<Self> {
        let path = absolute_lexical(path).map_err(|source| io_error(path, source))?;
        let directory = open_directory(&path)?;
        Ok(Self { path, directory })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn is_file(&self, relative: &Path) -> Result<bool> {
        is_open_file(self.open_relative(relative), &self.path.join(relative))
    }

    fn open_relative(&self, relative: &Path) -> Result<File> {
        open_beneath(&self.directory, &self.path, relative)
    }
}

pub(super) fn is_file_beneath(directory: &Path, relative: &Path) -> Result<bool> {
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
pub(super) fn walk_beneath(
    directory: &Path,
    max_depth: usize,
    visit: &mut impl FnMut(&Path, usize, RootedFileType) -> Result<()>,
) -> Result<()> {
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
    walk_directory(descriptor, &directory, Path::new(""), 0, max_depth, visit)
}

pub(super) fn with_manifest_roots<T>(
    roots: &[ManifestRoot],
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
    let result = operation();
    drop(guard);
    Ok(result)
}

struct ActiveRootsGuard(usize);

impl Drop for ActiveRootsGuard {
    fn drop(&mut self) {
        ACTIVE_ROOTS.with(|roots| roots.borrow_mut().truncate(self.0));
    }
}

pub(super) fn read(path: &Path) -> Result<String> {
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
pub(super) fn read_beneath(directory: &Path, relative: &Path) -> Result<String> {
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
pub(super) fn read_beneath(directory: &Path, relative: &Path) -> Result<String> {
    Err(manifest_error(
        &directory.join(relative),
        "safe manifest reads are unsupported on this platform",
    ))
}

fn read_open_file(path: &Path, file: File) -> Result<String> {
    let metadata = file.metadata().map_err(|source| io_error(path, source))?;
    if !metadata.file_type().is_file() {
        return Err(manifest_error(path, "manifest is not a regular file"));
    }
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err(manifest_error(
            path,
            format!("manifest exceeds the {MAX_MANIFEST_BYTES}-byte read limit"),
        ));
    }

    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(path, source))?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(manifest_error(
            path,
            format!("manifest exceeds the {MAX_MANIFEST_BYTES}-byte read limit"),
        ));
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
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NONBLOCK)
        .open(Path::new("/"))
        .map_err(|source| io_error(path, source))?;

    // `O_NOFOLLOW` protects only the final component passed to `open`. Traverse from the
    // filesystem root with descriptor-relative opens so no ancestor can redirect the root.
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                directory = open_at(
                    directory.as_raw_fd(),
                    Path::new(name),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                )
                .map_err(|source| io_error(path, source))?;
            }
            Component::ParentDir | Component::Prefix(_) => {
                return Err(manifest_error(
                    path,
                    "manifest root must be an absolute directory",
                ));
            }
        }
    }
    Ok(directory)
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
struct DirectoryStream(*mut libc::DIR);

#[cfg(unix)]
impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // SAFETY: the stream is uniquely owned by this guard.
        unsafe { libc::closedir(self.0) };
    }
}

#[cfg(unix)]
fn walk_directory(
    directory: File,
    root: &Path,
    relative: &Path,
    depth: usize,
    max_depth: usize,
    visit: &mut impl FnMut(&Path, usize, RootedFileType) -> Result<()>,
) -> Result<()> {
    let descriptor = directory.into_raw_fd();
    // SAFETY: ownership of `descriptor` is transferred to `fdopendir` on success.
    let stream = unsafe { libc::fdopendir(descriptor) };
    if stream.is_null() {
        let source = io::Error::last_os_error();
        // SAFETY: `fdopendir` failed, so ownership of `descriptor` remains here.
        drop(unsafe { File::from_raw_fd(descriptor) });
        return Err(io_error(&root.join(relative), source));
    }
    let stream = DirectoryStream(stream);

    loop {
        clear_errno();
        // SAFETY: `stream` remains valid and uniquely owned for the duration of the call.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let source = io::Error::last_os_error();
            if source.raw_os_error() == Some(0) {
                return Ok(());
            }
            return Err(io_error(&root.join(relative), source));
        }
        // SAFETY: `readdir` returned a valid entry whose name is NUL terminated.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        let name_path = Path::new(OsStr::from_bytes(name.to_bytes()));
        let child_relative = relative.join(name_path);
        let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: all pointers are valid and `status` is initialized on success.
        if unsafe {
            libc::fstatat(
                libc::dirfd(stream.0),
                name.as_ptr(),
                status.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(io_error(
                &root.join(&child_relative),
                io::Error::last_os_error(),
            ));
        }
        // SAFETY: `fstatat` succeeded.
        let status = unsafe { status.assume_init() };
        let kind = match status.st_mode & libc::S_IFMT {
            libc::S_IFDIR => RootedFileType::Directory,
            libc::S_IFREG => RootedFileType::File,
            libc::S_IFLNK => RootedFileType::Symlink,
            _ => RootedFileType::Other,
        };
        let child_depth = depth + 1;
        visit(&child_relative, child_depth, kind)?;
        if kind == RootedFileType::Directory && child_depth < max_depth {
            // SAFETY: `stream` is a valid open directory stream.
            let directory_fd = unsafe { libc::dirfd(stream.0) };
            let child = open_at(
                directory_fd,
                name_path,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
            .map_err(|source| io_error(&root.join(&child_relative), source))?;
            walk_directory(child, root, &child_relative, child_depth, max_depth, visit)?;
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn clear_errno() {
    // SAFETY: the platform returns a valid pointer to thread-local errno.
    unsafe { *libc::__error() = 0 };
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "ios"))))]
fn clear_errno() {
    // SAFETY: the platform returns a valid pointer to thread-local errno.
    unsafe { *libc::__errno_location() = 0 };
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
fn open_at(directory: RawFd, path: &Path, flags: i32) -> io::Result<File> {
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

fn io_error(path: &Path, source: io::Error) -> Error {
    Error::Io {
        operation: "read".to_owned(),
        path: path.to_owned(),
        source,
    }
}

pub(super) fn manifest_error(path: &Path, error: impl ToString) -> Error {
    Error::Manifest {
        path: path.to_owned(),
        message: error.to_string(),
    }
}

pub(super) fn strip_url_fragment(url: &str) -> String {
    url.split('#').next().unwrap_or(url).to_owned()
}

pub(super) fn github_archive(reference: &str) -> Option<(String, String)> {
    let reference = reference
        .split_once(" @ ")
        .map_or(reference.trim(), |(_, source)| source.trim());
    let (repository, commit) = reference
        .rsplit_once('#')
        .or_else(|| reference.rsplit_once(".git@"))?;
    if commit.len() != 40 || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let repository = repository.strip_prefix("git+").unwrap_or(repository);
    let repository = repository
        .strip_prefix("https://github.com/")
        .or_else(|| repository.strip_prefix("ssh://git@github.com/"))
        .or_else(|| repository.strip_prefix("git://github.com/"))
        .or_else(|| repository.strip_prefix("git@github.com:"))
        .or_else(|| repository.strip_prefix("github:"))
        .unwrap_or(repository);
    let repository = repository.strip_suffix(".git").unwrap_or(repository);
    let mut parts = repository.split('/');
    let owner = parts.next()?;
    let name = parts.next()?;
    if parts.next().is_some()
        || owner.is_empty()
        || name.is_empty()
        || !owner
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return None;
    }
    let commit = commit.to_ascii_lowercase();
    Some((
        format!("https://codeload.github.com/{owner}/{name}/tar.gz/{commit}"),
        commit,
    ))
}

#[cfg(test)]
mod tests;
