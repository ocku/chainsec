use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{
    error::{Error, Result},
    model::{DenoLockfileSnapshot, Dependency, Ecosystem, FetchMetadata},
};
use async_trait::async_trait;

use super::{
    Fetcher, PreparedFetch, SourceFetcher, cache::CacheLookup, filesystem::TrustedDir,
    network::NetworkBudget,
};

pub struct CacheStaging {
    pub(super) path: PathBuf,
    pub(super) name: PathBuf,
    pub(super) directory: TrustedDir,
}

#[derive(Clone)]
pub struct Acquisition {
    // Retained for diagnostics and tests; cache operations use `ecosystem`.
    pub(super) destination: PathBuf,
    pub(super) ecosystem: Arc<TrustedDir>,
    pub(super) locks: Arc<TrustedDir>,
    pub(super) lock_directory: PathBuf,
    pub(super) identity: String,
    pub(super) deno_lockfile: Option<DenoLockfileSnapshot>,
}

#[async_trait]
impl Fetcher for SourceFetcher {
    fn prepare_fetch(
        &self,
        dependency: Dependency,
        declared_from: PathBuf,
    ) -> Result<PreparedFetch> {
        let acquisition = (!dependency.is_local()
            && (dependency.is_resolved()
                || (dependency.ecosystem == Ecosystem::Deno
                    && dependency.requirement.starts_with("http"))))
        .then(|| self.acquisition(&dependency))
        .transpose()?;
        let acquisition_identity = acquisition
            .as_ref()
            .map(|acquisition| acquisition.identity.clone())
            .or_else(|| {
                dependency
                    .requires_registry_integrity()
                    .then(|| dependency.id())
            })
            .or_else(|| {
                dependency
                    .lockfile
                    .as_ref()
                    .map(|path| path.display().to_string())
            });
        Ok(PreparedFetch {
            dependency,
            declared_from,
            acquisition_identity,
            acquisition,
        })
    }

    async fn fetch_prepared(&self, prepared: PreparedFetch) -> Result<FetchMetadata> {
        self.fetch_prepared_dependency(prepared).await
    }

    async fn fetch(&self, dependency: Dependency, declared_from: PathBuf) -> Result<FetchMetadata> {
        let mut dependency = dependency;
        let mut budget = self.network_budget();
        self.resolve_unlocked_dependency_with_budget(&mut dependency, &mut budget)
            .await?;
        let prepared = self.prepare_fetch(dependency, declared_from)?;
        self.fetch_prepared_dependency_with_budget(prepared, &mut budget)
            .await
    }
}

impl SourceFetcher {
    async fn fetch_prepared_dependency(&self, prepared: PreparedFetch) -> Result<FetchMetadata> {
        let mut budget = self.network_budget();
        self.fetch_prepared_dependency_with_budget(prepared, &mut budget)
            .await
    }

    async fn fetch_prepared_dependency_with_budget(
        &self,
        prepared: PreparedFetch,
        budget: &mut NetworkBudget,
    ) -> Result<FetchMetadata> {
        let PreparedFetch {
            mut dependency,
            declared_from,
            acquisition,
            ..
        } = prepared;
        self.resolve_unlocked_dependency_with_budget(&mut dependency, budget)
            .await?;

        if dependency.is_local() {
            return self.fetch_local_dependency(&dependency, &declared_from);
        }
        if !dependency.is_resolved() {
            return Err(Error::Resolution {
                package: dependency.id(),
                message: "dependency has no locked version and integrity".to_owned(),
            });
        }
        let acquisition = acquisition.map_or_else(|| self.acquisition(&dependency), Ok)?;
        if let CacheLookup::Hit(cached) = self.cached(&dependency, &acquisition)? {
            return Ok(cached);
        }

        self.fetch_remote_dependency_with_budget(&dependency, &acquisition, budget)
            .await
    }

    #[allow(dead_code)]
    pub(super) async fn resolve_remote_root(&self, dependency: &mut Dependency) -> Result<()> {
        let mut budget = self.network_budget();
        self.resolve_remote_root_with_budget(dependency, &mut budget)
            .await
    }

    pub(super) async fn resolve_remote_root_with_budget(
        &self,
        dependency: &mut Dependency,
        budget: &mut NetworkBudget,
    ) -> Result<()> {
        if dependency.is_resolved() {
            return Ok(());
        }

        match dependency.ecosystem {
            Ecosystem::Python => {
                self.resolve_unlocked_python_with_budget(dependency, budget)
                    .await
            }
            Ecosystem::Npm => {
                self.resolve_unlocked_npm_with_budget(dependency, budget)
                    .await
            }
            Ecosystem::Deno if dependency.requirement.starts_with("jsr:") => {
                self.resolve_unlocked_jsr_with_budget(dependency, budget)
                    .await
            }
            Ecosystem::Deno => Err(Error::Resolution {
                package: dependency.id(),
                message: "unsupported remote root source".to_owned(),
            }),
        }
    }

    #[allow(dead_code)]
    async fn resolve_unlocked_dependency(&self, dependency: &mut Dependency) -> Result<()> {
        let mut budget = self.network_budget();
        self.resolve_unlocked_dependency_with_budget(dependency, &mut budget)
            .await
    }

    async fn resolve_unlocked_dependency_with_budget(
        &self,
        dependency: &mut Dependency,
        budget: &mut NetworkBudget,
    ) -> Result<()> {
        if dependency.is_local()
            || dependency.is_resolved()
            || (!dependency.requires_registry_integrity() && !self.policy.allow_unlocked)
        {
            return Ok(());
        }

        match dependency.ecosystem {
            Ecosystem::Python => {
                self.resolve_unlocked_python_with_budget(dependency, budget)
                    .await
            }
            Ecosystem::Npm => {
                self.resolve_unlocked_npm_with_budget(dependency, budget)
                    .await
            }
            Ecosystem::Deno if dependency.requirement.starts_with("npm:") => {
                self.resolve_unlocked_npm_with_budget(dependency, budget)
                    .await
            }
            Ecosystem::Deno if dependency.requirement.starts_with("jsr:") => {
                self.resolve_unlocked_jsr_with_budget(dependency, budget)
                    .await
            }
            Ecosystem::Deno => Ok(()),
        }
    }

    #[allow(dead_code)]
    pub(super) async fn fetch_remote_dependency(
        &self,
        dependency: &Dependency,
        acquisition: &Acquisition,
    ) -> Result<FetchMetadata> {
        let mut budget = self.network_budget();
        self.fetch_remote_dependency_with_budget(dependency, acquisition, &mut budget)
            .await
    }

    pub(super) async fn fetch_remote_dependency_with_budget(
        &self,
        dependency: &Dependency,
        acquisition: &Acquisition,
        budget: &mut NetworkBudget,
    ) -> Result<FetchMetadata> {
        let (url, repository_request) = self
            .artifact_request_with_budget(dependency, budget)
            .await?;
        let temporary = self.create_workspace_directory()?;
        let result = self
            .fetch_into_temporary(
                dependency,
                acquisition,
                &url,
                repository_request,
                &temporary,
                budget,
            )
            .await;
        if result.is_err() && temporary.exists() {
            let _ = fs::remove_dir_all(&temporary);
        }
        result
    }

    async fn fetch_into_temporary(
        &self,
        dependency: &Dependency,
        acquisition: &Acquisition,
        url: &url::Url,
        repository_request: bool,
        temporary: &Path,
        budget: &mut NetworkBudget,
    ) -> Result<FetchMetadata> {
        if dependency.is_pinned_github() {
            return self
                .fetch_github_archive(dependency, temporary, budget)
                .await;
        }

        match dependency.ecosystem {
            Ecosystem::Npm | Ecosystem::Python => {
                self.fetch_standalone_archive(
                    dependency,
                    acquisition,
                    url,
                    repository_request,
                    temporary,
                    budget,
                )
                .await
            }
            Ecosystem::Deno => {
                self.fetch_deno_package(
                    dependency,
                    acquisition,
                    url,
                    repository_request,
                    temporary,
                    budget,
                )
                .await
            }
        }
    }
}
