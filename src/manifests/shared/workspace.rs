use std::path::{Path, PathBuf};

use globset::GlobBuilder;

#[cfg(unix)]
use std::{
    ffi::{CStr, OsStr},
    fs::File,
    io,
    os::{
        fd::{FromRawFd, IntoRawFd},
        unix::ffi::OsStrExt,
    },
};

use crate::error::{Error, Result};

#[cfg(unix)]
use super::rooted_fs::{clone_root_directory, io_error, open_at};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::manifests) enum RootedFileType {
    Directory,
    File,
    Symlink,
    Other,
}

/// Retains a unique workspace member without allowing workspace expansion to exceed the same
/// configured package budget used by every manifest ecosystem.
pub(in crate::manifests) fn push_workspace_member_bounded(
    members: &mut Vec<PathBuf>,
    member: PathBuf,
    max_packages: usize,
) -> Result<()> {
    if members.contains(&member) {
        return Ok(());
    }
    if members.len() >= max_packages {
        return Err(Error::LimitExceeded {
            resource: "workspace members".to_owned(),
            limit: u64::try_from(max_packages).unwrap_or(u64::MAX),
        });
    }
    members.push(member);
    Ok(())
}

#[cfg(unix)]
pub(in crate::manifests) fn walk_beneath(
    directory: &Path,
    max_package_depth: usize,
    visit: &mut impl FnMut(&Path, usize, RootedFileType) -> Result<()>,
) -> Result<()> {
    let (directory, descriptor) = clone_root_directory(directory)?;
    walk_directory(
        descriptor,
        &directory,
        Path::new(""),
        0,
        max_package_depth,
        visit,
    )
}

#[cfg(unix)]
pub(in crate::manifests) fn walk_workspace_beneath(
    directory: &Path,
    max_package_depth: usize,
    max_entries: u64,
    visit: &mut impl FnMut(&Path, usize, RootedFileType) -> Result<()>,
) -> Result<()> {
    let mut visited_entries = 0u64;
    walk_beneath(directory, max_package_depth, &mut |entry, depth, kind| {
        visited_entries = visited_entries.saturating_add(1);
        if visited_entries > max_entries {
            return Err(Error::LimitExceeded {
                resource: "workspace entries".to_owned(),
                limit: max_entries,
            });
        }
        visit(entry, depth, kind)
    })
}

pub(in crate::manifests) fn workspace_depth_exceeded(
    kind: RootedFileType,
    depth: usize,
    max_package_depth: usize,
    included: bool,
) -> bool {
    kind == RootedFileType::Directory && depth >= max_package_depth && included
}

/// Returns whether an inclusion pattern can match a strict descendant of `boundary`.
///
/// Workspace walking cannot inspect directories at the configured depth boundary. This check is
/// intentionally conservative: it proves common irrelevant subtrees cannot match, but reports a
/// possible match whenever recursive glob semantics prevent that proof.
pub(in crate::manifests) fn workspace_pattern_may_match_descendant(
    patterns: &[String],
    boundary: &Path,
) -> bool {
    patterns.iter().any(|raw| {
        if raw.starts_with('!') {
            return false;
        }
        let pattern = raw.strip_prefix("./").unwrap_or(raw);
        include_pattern_may_match_descendant(pattern, boundary)
    })
}

fn include_pattern_may_match_descendant(pattern: &str, boundary: &Path) -> bool {
    let pattern_components = pattern.split('/').collect::<Vec<_>>();
    let boundary_component_count = boundary.components().count();
    if pattern_components
        .iter()
        .any(|component| component.is_empty())
    {
        return true;
    }

    if !pattern_components.contains(&"**") {
        if pattern_components.len() <= boundary_component_count {
            return false;
        }
        let prefix = pattern_components[..boundary_component_count].join("/");
        return GlobBuilder::new(&prefix)
            .literal_separator(true)
            .build()
            .map(|glob| glob.compile_matcher().is_match(boundary))
            .unwrap_or(true);
    }

    let mut boundary_components = boundary.components();
    for pattern_component in pattern_components {
        if pattern_component == "**" || contains_glob_meta(pattern_component) {
            return true;
        }
        let Some(boundary_component) = boundary_components.next() else {
            return true;
        };
        if boundary_component.as_os_str() != pattern_component {
            return false;
        }
    }

    false
}

fn contains_glob_meta(component: &str) -> bool {
    component
        .bytes()
        .any(|byte| matches!(byte, b'*' | b'?' | b'[' | b']' | b'{' | b'}'))
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
    max_package_depth: usize,
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
        if kind == RootedFileType::Directory && excluded_directory(name.to_bytes()) {
            continue;
        }
        let child_depth = depth + 1;
        visit(&child_relative, child_depth, kind)?;
        if kind == RootedFileType::Directory && child_depth < max_package_depth {
            // SAFETY: `stream` is a valid open directory stream.
            let directory_fd = unsafe { libc::dirfd(stream.0) };
            let child = open_at(
                directory_fd,
                name_path,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
            .map_err(|source| io_error(&root.join(&child_relative), source))?;
            walk_directory(
                child,
                root,
                &child_relative,
                child_depth,
                max_package_depth,
                visit,
            )?;
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
fn excluded_directory(name: &[u8]) -> bool {
    [
        b".git".as_slice(),
        b".chainsec-cache".as_slice(),
        b"node_modules".as_slice(),
        b"target".as_slice(),
        b".venv".as_slice(),
        b"venv".as_slice(),
        b"env".as_slice(),
        b"__pycache__".as_slice(),
    ]
    .contains(&name)
}
