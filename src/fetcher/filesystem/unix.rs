use std::{
    ffi::{CStr, CString, OsString},
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
        unix::ffi::{OsStrExt, OsStringExt},
    },
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use super::{split_parent, validate_child_name, validate_relative_path};

pub(in crate::fetcher) struct TrustedDir {
    file: File,
}

impl TrustedDir {
    pub(in crate::fetcher) fn metadata(&self) -> io::Result<std::fs::Metadata> {
        self.file.metadata()
    }

    pub(in crate::fetcher) fn open(path: &Path) -> io::Result<Self> {
        Ok(Self {
            file: open_directory_path_no_follow(path)?,
        })
    }

    /// Creates a uniquely named direct child directory and returns its name and
    /// an anchored handle to it.
    pub(in crate::fetcher) fn create_unique_child_dir(
        &self,
        prefix: &Path,
    ) -> io::Result<(PathBuf, Self)> {
        validate_child_name(prefix)?;

        for _ in 0..1024 {
            let name = unique_child_name(prefix);
            match mkdir_new_at(self.file.as_raw_fd(), &name, 0o700) {
                Ok(()) => {
                    let file = open_at(
                        self.file.as_raw_fd(),
                        &name,
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                        0,
                    )?;
                    return Ok((name, Self { file }));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create a unique child directory",
        ))
    }

    /// Lists the names of direct children. Names are not resolved through paths.
    pub(in crate::fetcher) fn list_child_names(&self) -> io::Result<Vec<PathBuf>> {
        read_dir_at(&self.file)
    }

    /// Removes a direct child, recursively when it is a directory, without
    /// traversing symlinks.
    pub(in crate::fetcher) fn remove_child_all(&self, name: &Path) -> io::Result<()> {
        validate_child_name(name)?;
        remove_at(self.file.as_raw_fd(), name)
    }

    /// Renames one direct child into another trusted directory. Neither name
    /// may contain a path separator or a traversal component.
    pub(in crate::fetcher) fn rename_child(
        &self,
        source: &Path,
        destination_directory: &TrustedDir,
        destination: &Path,
    ) -> io::Result<()> {
        validate_child_name(source)?;
        validate_child_name(destination)?;
        rename_at(
            self.file.as_raw_fd(),
            source,
            destination_directory.file.as_raw_fd(),
            destination,
        )
    }

    /// Opens a direct child directory, creating it if absent.
    pub(in crate::fetcher) fn open_or_create_child_dir(&self, name: &Path) -> io::Result<Self> {
        validate_child_name(name)?;
        match mkdir_new_at(self.file.as_raw_fd(), name, 0o700) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        Ok(Self {
            file: open_at(
                self.file.as_raw_fd(),
                name,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                0,
            )?,
        })
    }

    /// Opens or creates a writable direct child file without following a final
    /// symlink.
    pub(in crate::fetcher) fn open_or_create_child_file(&self, name: &Path) -> io::Result<File> {
        validate_child_name(name)?;
        open_at(
            self.file.as_raw_fd(),
            name,
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW,
            0o600,
        )
    }

    pub(in crate::fetcher) fn create_dir_all(&self, relative: &Path) -> io::Result<()> {
        let _ = self.open_directory(relative, true)?;
        Ok(())
    }

    pub(in crate::fetcher) fn open_subdirectory(&self, relative: &Path) -> io::Result<Self> {
        Ok(Self {
            file: self.open_directory(relative, false)?,
        })
    }

    /// Opens an existing file beneath this directory without following its final path component.
    ///
    /// Callers receive a non-blocking descriptor so an attacker cannot make a
    /// security-sensitive read block by replacing a file with a FIFO.
    pub(in crate::fetcher) fn open_file_no_follow(&self, relative: &Path) -> io::Result<File> {
        let (parent, name) = split_parent(relative)?;
        let directory = self.open_directory(parent, false)?;
        open_at(
            directory.as_raw_fd(),
            name,
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW,
            0,
        )
    }

    pub(in crate::fetcher) fn create_new_file(&self, relative: &Path) -> io::Result<File> {
        let (parent, name) = split_parent(relative)?;
        let directory = self.open_directory(parent, true)?;
        open_at(
            directory.as_raw_fd(),
            name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            0o600,
        )
    }

    fn open_directory(&self, relative: &Path, create: bool) -> io::Result<File> {
        validate_relative_path(relative, true)?;
        let mut current = self.file.try_clone()?;
        for component in relative.components() {
            let Component::Normal(name) = component else {
                continue;
            };
            let next = match open_at(
                current.as_raw_fd(),
                Path::new(name),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                0,
            ) {
                Ok(file) => file,
                Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                    mkdir_at(current.as_raw_fd(), Path::new(name), 0o700)?;
                    open_at(
                        current.as_raw_fd(),
                        Path::new(name),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                        0,
                    )?
                }
                Err(error) => return Err(error),
            };
            current = next;
        }
        Ok(current)
    }
}

static UNIQUE_CHILD_COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_child_name(prefix: &Path) -> PathBuf {
    let sequence = UNIQUE_CHILD_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut name = OsString::from(".");
    name.push(prefix.as_os_str());
    name.push(format!("-{}-{sequence}", std::process::id()));
    PathBuf::from(name)
}

fn open_directory_path_no_follow(path: &Path) -> io::Result<File> {
    let mut current = if path.is_absolute() {
        open_at(
            libc::AT_FDCWD,
            Path::new("/"),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            0,
        )?
    } else {
        open_at(
            libc::AT_FDCWD,
            Path::new("."),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            0,
        )?
    };

    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => {
                current = open_at(
                    current.as_raw_fd(),
                    Path::new(name),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                    0,
                )?;
            }
            Component::ParentDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "trusted directory path contains an unsupported component",
                ));
            }
        }
    }

    Ok(current)
}

fn c_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

fn open_at(directory: RawFd, path: &Path, flags: i32, mode: libc::mode_t) -> io::Result<File> {
    let path = c_path(path)?;
    // SAFETY: path is NUL terminated and the returned descriptor is owned here.
    let fd = unsafe {
        libc::openat(
            directory,
            path.as_ptr(),
            flags | libc::O_CLOEXEC,
            libc::c_uint::from(mode),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was returned by openat and is uniquely owned.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn mkdir_at(directory: RawFd, path: &Path, mode: libc::mode_t) -> io::Result<()> {
    match mkdir_new_at(directory, path, mode) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error),
    }
}

fn mkdir_new_at(directory: RawFd, path: &Path, mode: libc::mode_t) -> io::Result<()> {
    let path = c_path(path)?;
    // SAFETY: path is NUL terminated.
    if unsafe { libc::mkdirat(directory, path.as_ptr(), mode) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn read_dir_at(directory: &File) -> io::Result<Vec<PathBuf>> {
    let fd = directory.try_clone()?.into_raw_fd();
    // SAFETY: `fd` is uniquely owned and transferred to the DIR stream.
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        // SAFETY: fdopendir did not take ownership on failure.
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }

    let mut names = Vec::new();
    loop {
        set_errno_zero();
        // SAFETY: stream is valid until closed below.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            // SAFETY: stream is valid and no longer used after this call.
            unsafe { libc::closedir(stream) };
            return match error.raw_os_error() {
                Some(0) => Ok(names),
                _ => Err(error),
            };
        }
        // SAFETY: d_name is NUL-terminated for entries returned by readdir.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.push(PathBuf::from(OsString::from_vec(name.to_vec())));
        }
    }
}

fn remove_at(directory: RawFd, name: &Path) -> io::Result<()> {
    match unlink_at(directory, name, 0) {
        Ok(()) => return Ok(()),
        Err(error) if is_directory_unlink_error(&error) => {}
        Err(error) => return Err(error),
    }

    let child = open_at(
        directory,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        0,
    )?;
    for child_name in read_dir_at(&child)? {
        remove_at(child.as_raw_fd(), &child_name)?;
    }
    unlink_at(directory, name, libc::AT_REMOVEDIR)
}

fn unlink_at(directory: RawFd, name: &Path, flags: i32) -> io::Result<()> {
    let name = c_path(name)?;
    // SAFETY: name is NUL terminated.
    if unsafe { libc::unlinkat(directory, name.as_ptr(), flags) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn is_directory_unlink_error(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::EISDIR) | Some(libc::EPERM))
}

fn rename_at(
    source_directory: RawFd,
    source: &Path,
    destination_directory: RawFd,
    destination: &Path,
) -> io::Result<()> {
    let source = c_path(source)?;
    let destination = c_path(destination)?;
    // SAFETY: both names are NUL terminated and both descriptors remain valid.
    if unsafe {
        libc::renameat(
            source_directory,
            source.as_ptr(),
            destination_directory,
            destination.as_ptr(),
        )
    } == 0
    {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_errno_zero() {
    // SAFETY: errno is thread-local and this only prepares for readdir's error convention.
    unsafe { *libc::__errno_location() = 0 };
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn set_errno_zero() {
    // SAFETY: errno is thread-local and this only prepares for readdir's error convention.
    unsafe { *libc::__error() = 0 };
}
