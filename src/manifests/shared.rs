use std::{fs, path::Path};

use crate::error::{Error, Result};

pub(super) fn read(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|source| Error::Io {
        operation: "read".to_owned(),
        path: path.to_owned(),
        source,
    })
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
