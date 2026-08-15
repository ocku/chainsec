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

pub(crate) struct FetchRequest<'a> {
    pub(super) url: &'a url::Url,
    pub(super) repository_request: bool,
    pub(super) source_repository: Option<&'a url::Url>,
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
        budget.check()?;
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
        budget.check()?;
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
        budget.check()?;

        if dependency.is_local() {
            let fetched =
                self.fetch_local_dependency_with_budget(&dependency, &declared_from, budget)?;
            budget.check()?;
            return Ok(fetched);
        }
        if !dependency.is_resolved() {
            return Err(Error::Resolution {
                package: dependency.id(),
                message: "dependency has no locked version and integrity".to_owned(),
            });
        }
        let acquisition = acquisition.map_or_else(|| self.acquisition(&dependency), Ok)?;
        budget.check()?;
        let fetch_key = acquisition.identity.clone();
        let fetch_lock = self
            .fetch_locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(fetch_key.clone())
            .or_default()
            .clone();
        let _fetch_guard = tokio::time::timeout_at(budget.deadline(), fetch_lock.lock())
            .await
            .map_err(|_| budget.exceeded())?;
        budget.check()?;
        if let Some(fetched) = self
            .completed_fetches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&fetch_key)
            .cloned()
        {
            budget.check()?;
            return Ok(fetched);
        }

        let cache_fetcher = self.clone();
        let cache_dependency = dependency.clone();
        let cache_acquisition = acquisition.clone();
        let cache_deadline = budget.deadline_guard();
        let cached = tokio::task::spawn_blocking(move || {
            cache_fetcher.cached_before(&cache_dependency, &cache_acquisition, &cache_deadline)
        })
        .await
        .map_err(|error| Error::Fetch {
            package: dependency.id(),
            source_url: dependency
                .source_url
                .clone()
                .unwrap_or_else(|| dependency.requirement.clone()),
            message: format!("cache restoration worker failed: {error}"),
        })??;
        let fetched = if let CacheLookup::Hit(cached) = cached {
            budget.check()?;
            cached
        } else {
            budget.check()?;
            self.fetch_remote_dependency_with_budget(&dependency, &acquisition, budget)
                .await?
        };
        budget.check()?;
        self.completed_fetches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(fetch_key, fetched.clone());
        Ok(fetched)
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
            Ecosystem::Deno => Ok(()),
        }
    }

    pub(in crate::fetcher) fn effective_artifact_repository_request(
        &self,
        dependency: &Dependency,
        url: &url::Url,
        repository_request: bool,
    ) -> bool {
        // An allowlisted metadata-provided CDN is a direct request; only the configured
        // PyPI artifact base receives repository provenance and credentials.
        repository_request
            && (dependency.ecosystem != Ecosystem::Python
                || self.policy.repositories.pypi_artifact_url_is_permitted(url))
    }

    pub(super) async fn fetch_remote_dependency_with_budget(
        &self,
        dependency: &Dependency,
        acquisition: &Acquisition,
        budget: &mut NetworkBudget,
    ) -> Result<FetchMetadata> {
        let (url, repository_request, source_repository) = self
            .artifact_request_with_budget(dependency, budget)
            .await?;
        let repository_request =
            self.effective_artifact_repository_request(dependency, &url, repository_request);
        budget.check()?;
        let temporary = self.create_workspace_directory()?;
        budget.check()?;
        let request = FetchRequest {
            url: &url,
            repository_request,
            source_repository: source_repository.as_ref(),
        };
        let result = self
            .fetch_into_temporary(dependency, acquisition, request, &temporary, budget)
            .await
            .and_then(|metadata| {
                budget.check()?;
                Ok(metadata)
            });
        if result.is_err() && temporary.exists() && budget.check().is_ok() {
            let _ = fs::remove_dir_all(&temporary);
        }
        result
    }

    async fn fetch_into_temporary(
        &self,
        dependency: &Dependency,
        acquisition: &Acquisition,
        request: FetchRequest<'_>,
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
                self.fetch_standalone_archive(dependency, acquisition, request, temporary, budget)
                    .await
            }
            Ecosystem::Deno => {
                self.fetch_deno_package(dependency, acquisition, request, temporary, budget)
                    .await
            }
        }
    }
}
