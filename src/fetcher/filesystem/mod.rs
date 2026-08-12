//! Filesystem operations confined beneath an already-open directory.

use std::{
    io,
    path::{Component, Path},
};

mod unix;

pub(super) use unix::TrustedDir;

fn validate_child_name(name: &Path) -> io::Result<()> {
    match (name.components().next(), name.components().nth(1)) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "child name must be a single normal path component",
        )),
    }
}

fn validate_relative_path(path: &Path, allow_empty: bool) -> io::Result<()> {
    let mut count = 0;
    for component in path.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "relative path must contain only normal components",
            ));
        }
        count += 1;
    }
    if count == 0 && !allow_empty {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "relative path must not be empty",
        ));
    }
    Ok(())
}

fn split_parent(relative: &Path) -> io::Result<(&Path, &Path)> {
    let name = relative
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    validate_relative_path(parent, true)?;
    validate_child_name(Path::new(name))?;
    Ok((parent, Path::new(name)))
}

#[cfg(test)]
mod tests;
