use std::{fs::File, io::Read, path::Path};

use globset::{Glob, GlobSet, GlobSetBuilder};
use walkdir::DirEntry;

use crate::{
    error::{Error, Result},
    model::{EngineLimits, Language},
};

pub(super) const MAX_NON_SOURCE_ANALYSIS_BYTES: u64 = 1024 * 1024;

pub(super) fn language_for_entry(entry: &DirEntry, root: &Path) -> Result<Option<Language>> {
    let path = entry.path();
    let language = language_for(path, &[]);
    if language.is_some() {
        return Ok(language);
    }

    let file = open_scanned_file(path, root)?;
    let contents = read_file_prefix(file, path, 4096)?;
    Ok(language_for(path, &contents))
}

pub(super) fn read_entry_contents(
    entry: &DirEntry,
    root: &Path,
    language: Option<Language>,
    limits: &EngineLimits,
) -> Result<(Vec<u8>, u64)> {
    let path = entry.path();
    let file = open_scanned_file(path, root)?;
    let metadata = file.metadata().map_err(|error| scan_error(path, error))?;
    if !metadata.file_type().is_file() {
        return Err(Error::Scan {
            path: path.to_owned(),
            message: "file changed while it was being opened".to_owned(),
        });
    }
    let file_size = metadata.len();

    if language.is_some() && file_size > limits.max_source_file_bytes {
        return Err(Error::LimitExceeded {
            resource: format!("source file bytes ({})", path.display()),
            limit: limits.max_source_file_bytes,
        });
    }

    let limit = if language.is_some() {
        limits.max_source_file_bytes
    } else {
        MAX_NON_SOURCE_ANALYSIS_BYTES
    };
    let contents = if language.is_some() {
        read_bounded_file(file, path, limit)?
    } else {
        read_file_prefix(file, path, limit)?
    };
    let observed_size = if language.is_some() {
        contents.len() as u64
    } else {
        file_size
    };

    Ok((contents, observed_size))
}

fn open_scanned_file(path: &Path, root: &Path) -> Result<File> {
    #[cfg(unix)]
    {
        open_scanned_file_unix(path, root).map_err(|error| scan_error(path, error))
    }

    #[cfg(not(unix))]
    {
        File::open(path).map_err(|error| scan_error(path, error))
    }
}

#[cfg(unix)]
fn open_scanned_file_unix(path: &Path, root: &Path) -> std::io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    // A single-file scan has no directory traversal to pin, but still needs
    // O_NOFOLLOW for the final component.
    if root.is_file() {
        return open_no_follow(path, libc::AT_FDCWD);
    }

    let relative = path.strip_prefix(root).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path is outside scan root",
        )
    })?;
    let root_name = CString::new(root.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid scan root"))?;
    let root_fd = unsafe {
        libc::open(
            root_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if root_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut directory = unsafe { File::from_raw_fd(root_fd) };
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        let std::path::Component::Normal(name) = component else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid relative scan path",
            ));
        };
        let name = CString::new(name.as_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid scan path")
        })?;
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | if components.peek().is_some() {
                libc::O_DIRECTORY
            } else {
                0
            };
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let next = unsafe { File::from_raw_fd(fd) };
        if components.peek().is_some() {
            directory = next;
        } else {
            return Ok(next);
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "scan root is not a file",
    ))
}

#[cfg(unix)]
fn open_no_follow(path: &Path, directory_fd: std::os::fd::RawFd) -> std::io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;

    let name = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid scan path"))?;
    let fd = unsafe {
        if directory_fd == libc::AT_FDCWD {
            libc::open(
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        } else {
            libc::openat(
                directory_fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        }
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(test)]
fn read_source_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = open_scanned_file(path, path)?;
    read_bounded_file(file, path, limit)
}

fn read_bounded_file(mut file: File, path: &Path, limit: u64) -> Result<Vec<u8>> {
    let bytes = read_file_prefix(&mut file, path, limit.saturating_add(1))?;
    if bytes.len() as u64 > limit {
        return Err(Error::LimitExceeded {
            resource: format!("source file bytes ({})", path.display()),
            limit,
        });
    }
    Ok(bytes)
}

fn read_file_prefix(mut file: impl Read, path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.by_ref()
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| scan_error(path, error))?;
    Ok(bytes)
}

fn scan_error(path: &Path, error: std::io::Error) -> Error {
    Error::Scan {
        path: path.to_owned(),
        message: error.to_string(),
    }
}

pub(super) fn compile_ignored_paths(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }

    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(
            Glob::new(pattern).map_err(|error| Error::InvalidConfiguration {
                message: format!("invalid ignored path glob {pattern:?}: {error}"),
            })?,
        );
    }
    builder
        .build()
        .map(Some)
        .map_err(|error| Error::InvalidConfiguration {
            message: format!("could not build ignored path globs: {error}"),
        })
}

pub(super) fn included(
    entry: &DirEntry,
    root: &Path,
    ignored_paths: Option<&GlobSet>,
    exclude_node_modules: bool,
) -> bool {
    if entry.depth() == 0 {
        return true;
    }

    let relative = entry.path().strip_prefix(root).unwrap_or(entry.path());
    if ignored_paths.is_some_and(|patterns| patterns.is_match(relative)) {
        return false;
    }

    !(matches!(
        entry.file_name().to_str(),
        Some(
            ".git"
                | ".chainsec-cache"
                | ".chainsec-cache.lock"
                | "target"
                | ".venv"
                | "venv"
                | "__pycache__"
        )
    ) || (exclude_node_modules && entry.file_name().to_str() == Some("node_modules")))
}

pub(super) fn is_test_fixture(path: &Path) -> bool {
    let components = path
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect::<Vec<_>>();

    components.iter().any(|component| {
        matches!(
            *component,
            "fixtures" | "fixture" | "testdata" | "__fixtures__"
        )
    }) || components.iter().enumerate().any(|(index, component)| {
        matches!(*component, "test" | "tests")
            && components[index + 1..]
                .iter()
                .any(|component| matches!(*component, "data" | "resources"))
    })
}

pub(super) fn language_for(path: &Path, contents: &[u8]) -> Option<Language> {
    if let Some(extension) = path.extension().and_then(|extension| extension.to_str()) {
        let extension = extension.to_ascii_lowercase();
        match extension.as_str() {
            "py" | "pyi" => return Some(Language::Python),
            "js" | "mjs" | "cjs" | "jsx" => return Some(Language::JavaScript),
            "ts" | "mts" | "cts" | "tsx" => return Some(Language::TypeScript),
            _ => {}
        }
    }

    shebang_language(contents)
}

fn shebang_language(contents: &[u8]) -> Option<Language> {
    let first_line = contents.split(|byte| *byte == b'\n').next()?;
    let line = std::str::from_utf8(first_line)
        .ok()?
        .strip_prefix("#!")?
        .trim();
    let mut words = line.split_whitespace();
    let interpreter = words.next()?.rsplit('/').next()?;
    let interpreter = if interpreter == "env" {
        words
            .find(|word| !word.starts_with('-') && !word.contains('='))?
            .rsplit('/')
            .next()?
    } else {
        interpreter
    };

    match interpreter.to_ascii_lowercase().as_str() {
        "python" | "python2" | "python3" | "pypy" | "pypy3" => Some(Language::Python),
        "node" | "nodejs" | "deno" | "bun" => Some(Language::JavaScript),
        "ts-node" | "ts-node-esm" | "tsx" => Some(Language::TypeScript),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
