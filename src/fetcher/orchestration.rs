use std::{fs, path::PathBuf, sync::Mutex};

use crate::{
    error::{Error, Result},
    model::{Dependency, Ecosystem, EngineLimits, FetchMetadata},
};
use reqwest::{Client, redirect::Policy};

use super::{
    FetchPolicy, RemoteVersionSelection, SourceFetcher,
    cache::{self, CacheLookup},
    policy::validate_repository_transport,
    workspace::restrict_workspace_directory,
};

impl SourceFetcher {
    /// Builds the async HTTP client, or returns `None` in offline mode.
    fn build_client(policy: &FetchPolicy) -> Option<Result<Client>> {
        if policy.offline {
            return None;
        }
        let request_timeout = policy.request_timeout;
        Some(
            Client::builder()
                .timeout(request_timeout)
                .no_proxy()
                // Redirects are handled by `network::download` so credentials are
                // re-evaluated for every destination instead of forwarded by the client.
                .redirect(Policy::none())
                .user_agent(concat!("chainsec/", env!("CARGO_PKG_VERSION")))
                .build()
                .map_err(|error| Error::InvalidConfiguration {
                    message: error.to_string(),
                }),
        )
    }

    pub fn new(cache: PathBuf, policy: FetchPolicy, limits: EngineLimits) -> Result<Self> {
        validate_repository_transport(&policy)?;
        let (cache, cache_root, cache_locks, cache_lock_directory, lifecycle_lock) =
            cache::prepare_cache(&cache)?;
        let workspace_root = tempfile::Builder::new()
            .prefix("chainsec-workspaces-")
            .tempdir()
            .map_err(|source| Error::Io {
                operation: "create private workspace root".to_owned(),
                path: std::env::temp_dir(),
                source,
            })?;
        restrict_workspace_directory(workspace_root.path(), "restrict private workspace root")?;
        let workspace_root_path =
            fs::canonicalize(workspace_root.path()).map_err(|source| Error::Io {
                operation: "resolve private workspace root".to_owned(),
                path: workspace_root.path().to_owned(),
                source,
            })?;
        let client = Self::build_client(&policy).transpose()?;
        Ok(Self {
            cache,
            cache_root,
            cache_locks,
            cache_lock_directory,
            policy,
            limits,
            client,
            workspaces: Mutex::new(Vec::new()),
            workspace_root_path,
            _workspace_root: workspace_root,
            _lifecycle_lock: lifecycle_lock,
        })
    }

    /// Resolves the selected registry release and up to `count - 1` older releases.
    /// `count` must be at least two so the result can provide a diff baseline.
    ///
    /// Results are semantically ordered newest to oldest and are fully pinned for
    /// [`Self::fetch_remote_root`]. Older releases without a supported artifact and
    /// integrity are skipped.
    pub async fn resolve_remote_versions(
        &self,
        dependency: Dependency,
        count: usize,
    ) -> Result<Vec<Dependency>> {
        self.resolve_remote_version_selection(dependency, RemoteVersionSelection::Last(count))
            .await
    }

    /// Resolves registry releases using ecosystem-native version ordering.
    ///
    /// Explicit comparisons return `[TO, FROM]`. Ranges include every pullable
    /// release between their endpoints and are ordered newest to oldest.
    pub async fn resolve_remote_version_selection(
        &self,
        dependency: Dependency,
        selection: RemoteVersionSelection,
    ) -> Result<Vec<Dependency>> {
        if matches!(selection, RemoteVersionSelection::Last(count) if count < 2) {
            return Err(Error::InvalidConfiguration {
                message:
                    "remote version diffs require at least 2 versions for a comparison baseline"
                        .to_owned(),
            });
        }
        if dependency.is_pinned_github() {
            return Err(Error::InvalidConfiguration {
                message: "pinned GitHub dependencies have no registry version history".to_owned(),
            });
        }
        if dependency.is_local() {
            return Err(Error::InvalidConfiguration {
                message: "local dependencies have no registry version history".to_owned(),
            });
        }

        let package = dependency.id();
        let mut budget = self.network_budget();
        let dependencies = match dependency.ecosystem {
            Ecosystem::Python => {
                self.resolve_python_version_selection_with_budget(
                    dependency,
                    selection,
                    &mut budget,
                )
                .await?
            }
            Ecosystem::Npm => {
                self.resolve_npm_version_selection_with_budget(dependency, selection, &mut budget)
                    .await?
            }
            Ecosystem::Deno if dependency.requirement.starts_with("jsr:") => {
                self.resolve_jsr_version_selection_with_budget(dependency, selection, &mut budget)
                    .await?
            }
            Ecosystem::Deno => {
                return Err(Error::Resolution {
                    package: dependency.id(),
                    message: "remote version history is supported only for npm, PyPI, and JSR registry selectors".to_owned(),
                });
            }
        };
        self.enforce_remote_version_limit(dependencies.len())?;
        if dependencies.len() < 2 {
            return Err(Error::Resolution {
                package,
                message: "version diff resolved fewer than 2 pullable releases; no comparison baseline is available"
                    .to_owned(),
            });
        }
        Ok(dependencies)
    }

    pub(in crate::fetcher) fn enforce_remote_version_limit(&self, count: usize) -> Result<()> {
        self.enforce_version_limit(count, "remote version roots")
    }

    pub(in crate::fetcher) fn enforce_remote_version_candidate_limit(
        &self,
        count: usize,
    ) -> Result<()> {
        self.enforce_version_limit(count, "remote version candidates")
    }

    fn enforce_version_limit(&self, count: usize, resource: &str) -> Result<()> {
        if count > self.limits.max_packages {
            return Err(Error::LimitExceeded {
                resource: resource.to_owned(),
                limit: u64::try_from(self.limits.max_packages).unwrap_or(u64::MAX),
            });
        }
        Ok(())
    }

    /// Fetches an explicitly requested remote package root.
    ///
    /// Temporary source remains available until this `SourceFetcher` is dropped.
    /// Unlike discovered dependencies, a remote root is intentionally allowed to
    /// resolve through its registry without a lockfile. Its discovered dependencies
    /// still use the normal fetch policy.
    pub async fn fetch_remote_root(&self, dependency: Dependency) -> Result<FetchMetadata> {
        let mut dependency = dependency;
        let mut budget = self.network_budget();
        self.resolve_remote_root_with_budget(&mut dependency, &mut budget)
            .await?;

        if !dependency.is_resolved() {
            return Err(Error::Resolution {
                package: dependency.id(),
                message: "remote root has no resolved version and integrity".to_owned(),
            });
        }
        let acquisition = self.acquisition(&dependency)?;
        if let CacheLookup::Hit(cached) = self.cached(&dependency, &acquisition)? {
            return Ok(cached);
        }

        self.fetch_remote_dependency_with_budget(&dependency, &acquisition, &mut budget)
            .await
    }
}
