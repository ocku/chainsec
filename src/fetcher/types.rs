use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use crate::{
    error::Result,
    model::{Dependency, Ecosystem, EngineLimits, FetchMetadata},
};
use async_trait::async_trait;
use reqwest::Client;

use super::{Acquisition, FetchPolicy, cache::CacheLock, filesystem::TrustedDir};

#[async_trait]
pub trait Fetcher: Sync {
    fn prepare_fetch(
        &self,
        dependency: Dependency,
        declared_from: PathBuf,
    ) -> Result<PreparedFetch> {
        Ok(PreparedFetch::new(dependency, declared_from))
    }

    async fn fetch_prepared(&self, prepared: PreparedFetch) -> Result<FetchMetadata> {
        self.fetch(prepared.dependency, prepared.declared_from)
            .await
    }

    async fn fetch(&self, dependency: Dependency, declared_from: PathBuf) -> Result<FetchMetadata>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteVersionSelection {
    Last(usize),
    Compare { from: String, to: String },
    Range { from: String, to: String },
}

pub struct SourceFetcher {
    // This path is retained solely for diagnostics and test-facing cache destinations.
    pub(in crate::fetcher) cache: PathBuf,
    pub(in crate::fetcher) cache_root: TrustedDir,
    // Stored beside the cache with owner-only permissions, so cache writers cannot
    // replace lock inodes and split advisory locking.
    pub(in crate::fetcher) cache_locks: Arc<TrustedDir>,
    pub(in crate::fetcher) cache_lock_directory: PathBuf,
    pub(in crate::fetcher) policy: FetchPolicy,
    pub(in crate::fetcher) limits: EngineLimits,
    pub(in crate::fetcher) client: Option<Client>,
    pub(in crate::fetcher) workspaces: Mutex<Vec<ScanWorkspace>>,
    // Use the canonical path when reopening workspace directories with `O_NOFOLLOW`.
    // macOS exposes its temporary directory through `/var`, which is a symlink to
    // `/private/var` and would otherwise be rejected as an unsafe path component.
    pub(in crate::fetcher) workspace_root_path: PathBuf,
    // `TempDir` creates this root atomically with owner-only permissions. Keeping it
    // after `workspaces` ensures individual workspaces are removed before the root.
    pub(in crate::fetcher) _workspace_root: tempfile::TempDir,
    pub(in crate::fetcher) _lifecycle_lock: CacheLock,
}

pub(in crate::fetcher) struct ScanWorkspace {
    pub(in crate::fetcher) root: PathBuf,
}

#[derive(Clone)]
pub struct PreparedFetch {
    pub(crate) dependency: Dependency,
    pub(crate) declared_from: PathBuf,
    pub(crate) acquisition_identity: Option<String>,
    pub(in crate::fetcher) acquisition: Option<Acquisition>,
}

impl PreparedFetch {
    fn new(dependency: Dependency, declared_from: PathBuf) -> Self {
        let acquisition_identity = if dependency.ecosystem == Ecosystem::Deno
            && dependency.requirement.starts_with("http")
        {
            dependency
                .deno_lockfile_snapshot
                .as_ref()
                .map(|snapshot| snapshot.identity().to_owned())
        } else {
            None
        };
        Self {
            dependency,
            declared_from,
            acquisition_identity,
            acquisition: None,
        }
    }
}
