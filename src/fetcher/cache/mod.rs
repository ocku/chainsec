mod metadata;
mod publication;
mod restoration;
mod storage;

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    error::{Error, Result},
    model::{Dependency, Ecosystem},
};

use super::{Acquisition, SourceFetcher};

use self::storage::validate_cache_directory;

pub(super) use storage::{CacheLock, prepare_cache, purge_cache};
pub(in crate::fetcher) use storage::{is_unsafe_cache_open_error, write_cached_artifact};

const CACHED_ARTIFACT: &str = ".artifact";
const COMPLETION_MARKER: &str = ".complete.json";
const MAX_COMPLETION_MARKER_BYTES: u64 = 64 * 1024;
const UNVERIFIED_CACHE_SOURCE_URL: &str = "cache:integrity-verified-artifact";
const CACHE_IDENTITY_FORMAT: &[u8] = b"chainsec.cache.identity.v1";

pub(super) enum CacheLookup<T> {
    Hit(T),
    Miss,
    InvalidEntry,
}

pub(in crate::fetcher) struct CachePublication<'a> {
    pub(in crate::fetcher) dependency: &'a Dependency,
    pub(in crate::fetcher) acquisition: &'a Acquisition,
    pub(in crate::fetcher) source_url: &'a Url,
    pub(in crate::fetcher) effective_source_url: Option<&'a Url>,
    pub(in crate::fetcher) digest: String,
    pub(in crate::fetcher) temporary: &'a Path,
    pub(in crate::fetcher) source_directory: &'a Path,
}

fn is_deno_graph(dependency: &Dependency) -> bool {
    dependency.ecosystem == Ecosystem::Deno
        && dependency.requirement.starts_with("http")
        && Url::parse(&dependency.requirement)
            .ok()
            .is_some_and(|url| !url.path().ends_with(".tgz"))
}

fn hash_cache_identity_field(hasher: &mut Sha256, tag: u8, value: Option<&str>) {
    hasher.update([tag]);
    match value {
        Some(value) => {
            hasher.update([1]);
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
        }
        None => hasher.update([0]),
    }
}

fn cache_identity(dependency: &Dependency, deno_lockfile: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CACHE_IDENTITY_FORMAT);
    hash_cache_identity_field(&mut hasher, 1, Some(&dependency.id()));
    hash_cache_identity_field(&mut hasher, 2, dependency.source_url.as_deref());
    hash_cache_identity_field(&mut hasher, 3, deno_lockfile);
    hex::encode(hasher.finalize())
}

fn workspace_source_path(
    dependency: &Dependency,
    source_url: &Url,
    temporary: &Path,
    source_directory: &Path,
) -> Result<PathBuf> {
    source_directory
        .strip_prefix(temporary)
        .map(|relative| temporary.join(relative))
        .map_err(|error| Error::Fetch {
            package: dependency.id(),
            source_url: source_url.to_string(),
            message: error.to_string(),
        })
}

impl SourceFetcher {
    pub(super) fn acquisition(&self, dependency: &Dependency) -> Result<Acquisition> {
        let deno_lockfile = (dependency.ecosystem == Ecosystem::Deno
            && dependency.requirement.starts_with("http"))
        .then(|| dependency.deno_lockfile_snapshot.clone())
        .flatten();
        let key = cache_identity(
            dependency,
            deno_lockfile.as_ref().map(|lockfile| lockfile.identity()),
        );
        let ecosystem_name = dependency.ecosystem.to_string();
        let ecosystem_path = self.cache.join(&ecosystem_name);
        let ecosystem = self
            .cache_root
            .open_or_create_child_dir(Path::new(&ecosystem_name))
            .map_err(|source| {
                if is_unsafe_cache_open_error(&source) {
                    Error::Policy {
                        operation: "cache confinement".to_owned(),
                        message: format!(
                            "cache ecosystem is not a regular directory: {}",
                            ecosystem_path.display()
                        ),
                    }
                } else {
                    Error::Io {
                        operation: "create ecosystem cache".to_owned(),
                        path: ecosystem_path.clone(),
                        source,
                    }
                }
            })?;
        validate_cache_directory(&ecosystem, &ecosystem_path, "cache ecosystem directory")?;
        Ok(Acquisition {
            destination: ecosystem_path.join(&key),
            ecosystem: Arc::new(ecosystem),
            locks: self.cache_locks.clone(),
            lock_directory: self.cache_lock_directory.clone(),
            identity: key,
            deno_lockfile,
        })
    }
}

#[cfg(test)]
mod tests;
