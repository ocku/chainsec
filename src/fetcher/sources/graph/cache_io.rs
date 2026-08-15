use std::{collections::HashSet, fs, io::Read, path::Path};

use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    error::{Error, Result},
    fetcher::{
        budget::AcquisitionDeadline, cache::is_unsafe_cache_open_error, filesystem::TrustedDir,
    },
    model::DenoLockfileSnapshot,
};

use super::canonical_graph_url;

pub(super) fn lockfile_redirect_effective_url(
    lockfile: Option<&DenoLockfileSnapshot>,
    requested_url: &Url,
    max_redirect_hops: usize,
    deadline: &AcquisitionDeadline,
) -> Result<Option<Url>> {
    let Some(lockfile) = lockfile else {
        return Ok(None);
    };
    let redirects = lockfile.redirects();
    let mut current = canonical_graph_url(requested_url);
    let mut visited = HashSet::new();
    for hops in 0..=max_redirect_hops {
        deadline.check()?;
        if !visited.insert(current.clone()) {
            return Err(Error::Policy {
                operation: "cache validation".to_owned(),
                message: format!(
                    "Deno lockfile redirect chain for {requested_url} contains a cycle at {current}"
                ),
            });
        }
        let Some(target) = redirects.get(&current) else {
            if hops == 0 {
                return Ok(None);
            }
            return Url::parse(&current).map(Some).map_err(|error| Error::Policy {
                operation: "cache validation".to_owned(),
                message: format!(
                    "Deno lockfile redirect chain for {requested_url} has invalid target {current}: {error}"
                ),
            });
        };
        if hops == max_redirect_hops {
            return Err(Error::Policy {
                operation: "cache validation".to_owned(),
                message: format!(
                    "Deno lockfile redirect chain for {requested_url} exceeds the redirect limit"
                ),
            });
        }
        current.clone_from(target);
    }
    unreachable!("bounded Deno lockfile redirect traversal must return")
}

pub(super) fn cached_graph_module_filename(canonical_url: &str, extension: &str) -> String {
    format!(
        "{}.{}",
        hex::encode(Sha256::digest(canonical_url.as_bytes())),
        extension
    )
}

pub(super) fn open_cached_directory(source: &Path, label: &str) -> Result<TrustedDir> {
    TrustedDir::open(source).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound || is_unsafe_cache_open_error(&error) {
            Error::Policy {
                operation: "cache validation".to_owned(),
                message: format!("{label} is missing or unsafe: {}", source.display()),
            }
        } else {
            Error::Io {
                operation: format!("open {label}"),
                path: source.to_owned(),
                source: error,
            }
        }
    })
}

#[cfg(test)]
pub(super) fn read_cached_graph_module(
    source: &TrustedDir,
    source_path: &Path,
    filename: &str,
    limit: u64,
) -> Result<Vec<u8>> {
    let deadline = crate::fetcher::budget::AcquisitionBudget::new(
        std::time::Duration::from_secs(3_600),
        u64::MAX,
    )
    .deadline_guard();
    read_cached_graph_module_before(source, source_path, filename, limit, &deadline)
}

pub(super) fn read_cached_graph_module_before(
    source: &TrustedDir,
    source_path: &Path,
    filename: &str,
    limit: u64,
    deadline: &AcquisitionDeadline,
) -> Result<Vec<u8>> {
    deadline.check()?;
    let path = source_path.join(filename);
    let file = source
        .open_file_no_follow(Path::new(filename))
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound || is_unsafe_cache_open_error(&error) {
                Error::Policy {
                    operation: "cache validation".to_owned(),
                    message: format!(
                        "cached Deno module is missing or unsafe: {}",
                        path.display()
                    ),
                }
            } else {
                Error::Io {
                    operation: "open cached Deno module".to_owned(),
                    path: path.clone(),
                    source: error,
                }
            }
        })?;
    let metadata = file.metadata().map_err(|source| Error::Io {
        operation: "inspect opened cached Deno module".to_owned(),
        path: path.clone(),
        source,
    })?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(Error::Policy {
            operation: "cache validation".to_owned(),
            message: format!(
                "cached Deno module is unsafe or exceeds the download limit: {}",
                path.display()
            ),
        });
    }

    read_bounded_file(file, &path, limit, "cached Deno module bytes", deadline)
}

pub(super) fn read_bounded_file(
    file: fs::File,
    path: &Path,
    limit: u64,
    limit_resource: &str,
    deadline: &AcquisitionDeadline,
) -> Result<Vec<u8>> {
    let metadata = file.metadata().map_err(|source| Error::Io {
        operation: "inspect cached Deno metadata".to_owned(),
        path: path.to_owned(),
        source,
    })?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(Error::Policy {
            operation: "cache validation".to_owned(),
            message: format!(
                "cached Deno metadata is not a bounded regular file: {}",
                path.display()
            ),
        });
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    let mut reader = file.take(limit.saturating_add(1));
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        deadline.check()?;
        let read = reader.read(&mut buffer).map_err(|source| Error::Io {
            operation: "read cached Deno metadata".to_owned(),
            path: path.to_owned(),
            source,
        })?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.len() as u64 > limit {
            return Err(Error::LimitExceeded {
                resource: limit_resource.to_owned(),
                limit,
            });
        }
    }
    deadline.check()?;
    Ok(bytes)
}
