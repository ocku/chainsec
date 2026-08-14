mod acquisition;
mod archive;
mod budget;
mod cache;
mod credentials;
mod filesystem;
mod integrity;
mod network;
mod orchestration;
mod policy;
mod repository;
mod sources;
mod types;
mod workspace;

use std::path::Path;

use crate::error::Result;

pub(super) use acquisition::{Acquisition, CacheStaging, FetchRequest};
pub use policy::FetchPolicy;
pub use repository::ArtifactRepositories;
pub use types::{Fetcher, PreparedFetch, RemoteVersionSelection, SourceFetcher};

use policy::host_is_allowed;

pub fn purge_cache(path: &Path) -> Result<bool> {
    cache::purge_cache(path)
}

#[cfg(test)]
mod tests;
