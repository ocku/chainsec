use std::{fs::File, io::Read, path::Path};

#[cfg(unix)]
use std::ffi::OsString;

use globset::{Glob, GlobSet, GlobSetBuilder};
use walkdir::DirEntry;

use crate::{
    error::{Error, Result},
    model::{EngineLimits, Language},
};

pub(super) const MAX_NON_SOURCE_ANALYSIS_BYTES: u64 = 1024 * 1024;

#[cfg(test)]
pub(super) fn read_entry(
    entry: &DirEntry,
    root: &Path,
    limits: &EngineLimits,
    extension_language: Option<Language>,
) -> Result<(Option<Language>, Vec<u8>, u64)> {
    let mut opener = ScannedFileOpener::new(root)?;
    read_entry_with_opener(entry, &mut opener, limits, extension_language)
}

pub(super) fn read_entry_with_opener(
    entry: &DirEntry,
    opener: &mut ScannedFileOpener<'_>,
    limits: &EngineLimits,
    extension_language: Option<Language>,
) -> Result<(Option<Language>, Vec<u8>, u64)> {
    let path = entry.path();
    let mut file = opener.open(path)?;
    let metadata = file.metadata().map_err(|error| scan_error(path, error))?;
    if !metadata.file_type().is_file() {
        return Err(Error::Scan {
            path: path.to_owned(),
            message: "file changed while it was being opened".to_owned(),
        });
    }
    let file_size = metadata.len();
    let mut contents = if extension_language.is_some() {
        Vec::new()
    } else {
        read_file_prefix(&mut file, path, 4096)?
    };
    let language = extension_language.or_else(|| language_for(path, &contents));

    if language.is_some() && file_size > limits.max_source_file_size {
        return Err(Error::LimitExceeded {
            resource: format!("source file bytes ({})", path.display()),
            limit: limits.max_source_file_size,
        });
    }

    if language.is_some() {
        read_bounded_file_into(&mut file, path, limits.max_source_file_size, &mut contents)?;
    } else {
        read_file_prefix_into(
            &mut file,
            path,
            MAX_NON_SOURCE_ANALYSIS_BYTES,
            &mut contents,
        )?;
    }
    let observed_size = if language.is_some() {
        contents.len() as u64
    } else {
        file_size
    };

    Ok((language, contents, observed_size))
}

pub(super) struct ScannedFileOpener<'a> {
    root: &'a Path,
    #[cfg(unix)]
    root_directory: Option<File>,
    #[cfg(unix)]
    directory_stack: Vec<(OsString, File)>,
}

impl<'a> ScannedFileOpener<'a> {
    pub(super) fn new(root: &'a Path) -> Result<Self> {
        #[cfg(unix)]
        let root_directory = if root.is_file() {
            None
        } else {
            Some(open_directory_no_follow(root).map_err(|error| scan_error(root, error))?)
        };

        Ok(Self {
            root,
            #[cfg(unix)]
            root_directory,
            #[cfg(unix)]
            directory_stack: Vec::new(),
        })
    }

    fn open(&mut self, path: &Path) -> Result<File> {
        #[cfg(unix)]
        {
            self.open_unix(path)
                .map_err(|error| scan_error(path, error))
        }

        #[cfg(not(unix))]
        {
            File::open(path).map_err(|error| scan_error(path, error))
        }
    }

    #[cfg(unix)]
    fn open_unix(&mut self, path: &Path) -> std::io::Result<File> {
        use std::os::fd::AsRawFd;

        // A single-file scan has no directory traversal to pin, but still needs
        // O_NOFOLLOW for the final component.
        let Some(root_directory) = &self.root_directory else {
            return open_no_follow(path, libc::AT_FDCWD);
        };
        let relative = path.strip_prefix(self.root).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path is outside scan root",
            )
        })?;
        let components = relative
            .components()
            .map(|component| match component {
                std::path::Component::Normal(name) => Ok(name.to_os_string()),
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid relative scan path",
                )),
            })
            .collect::<std::io::Result<Vec<_>>>()?;
        let Some((file_name, directories)) = components.split_last() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "scan root is not a file",
            ));
        };

        let common_depth = self
            .directory_stack
            .iter()
            .zip(directories)
            .take_while(|((cached, _), requested)| cached == *requested)
            .count();
        self.directory_stack.truncate(common_depth);

        for directory_name in &directories[common_depth..] {
            let parent_fd = self
                .directory_stack
                .last()
                .map_or(root_directory.as_raw_fd(), |(_, directory)| {
                    directory.as_raw_fd()
                });
            let directory = open_component_no_follow(directory_name, parent_fd, true)?;
            self.directory_stack
                .push((directory_name.clone(), directory));
        }

        let parent_fd = self
            .directory_stack
            .last()
            .map_or(root_directory.as_raw_fd(), |(_, directory)| {
                directory.as_raw_fd()
            });
        open_component_no_follow(file_name, parent_fd, false)
    }
}

#[cfg(unix)]
fn open_directory_no_follow(path: &Path) -> std::io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;

    let name = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid scan root"))?;
    let fd = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn open_component_no_follow(
    name: &std::ffi::OsStr,
    directory_fd: std::os::fd::RawFd,
    directory: bool,
) -> std::io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;

    let name = CString::new(name.as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid scan path"))?;
    let flags = libc::O_RDONLY
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | if directory { libc::O_DIRECTORY } else { 0 };
    let fd = unsafe { libc::openat(directory_fd, name.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(test)]
fn open_scanned_file(path: &Path, root: &Path) -> Result<File> {
    ScannedFileOpener::new(root)?.open(path)
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

#[cfg(test)]
fn read_bounded_file(mut file: File, path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    read_bounded_file_into(&mut file, path, limit, &mut bytes)?;
    Ok(bytes)
}

fn read_bounded_file_into(
    file: &mut File,
    path: &Path,
    limit: u64,
    bytes: &mut Vec<u8>,
) -> Result<()> {
    read_file_prefix_into(file, path, limit.saturating_add(1), bytes)?;
    if bytes.len() as u64 > limit {
        return Err(Error::LimitExceeded {
            resource: format!("source file bytes ({})", path.display()),
            limit,
        });
    }
    Ok(())
}

fn read_file_prefix(mut file: impl Read, path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    read_file_prefix_into(&mut file, path, limit, &mut bytes)?;
    Ok(bytes)
}

fn read_file_prefix_into(
    file: &mut impl Read,
    path: &Path,
    limit: u64,
    bytes: &mut Vec<u8>,
) -> Result<()> {
    let remaining = limit.saturating_sub(bytes.len() as u64);
    file.take(remaining)
        .read_to_end(bytes)
        .map_err(|error| scan_error(path, error))?;
    Ok(())
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
