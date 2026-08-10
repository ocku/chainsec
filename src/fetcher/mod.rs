mod archive;
mod cache;
mod credentials;
mod integrity;
mod network;
mod repository;
mod sources;

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    error::{Error, Result},
    model::{Dependency, Ecosystem, EngineLimits, FetchMetadata},
};
use async_trait::async_trait;
use reqwest::{Client, redirect::Policy};

pub use repository::ArtifactRepositories;

static TEMPORARY_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct FetchPolicy {
    pub offline: bool,
    pub allow_unlocked: bool,
    pub allowed_hosts: Vec<String>,
    pub repositories: ArtifactRepositories,
    pub request_timeout: Duration,
    pub max_redirects: usize,
    pub max_deno_modules: usize,
    pub trust_local_input: bool,
}

impl Default for FetchPolicy {
    fn default() -> Self {
        Self {
            offline: true,
            allow_unlocked: false,
            allowed_hosts: Vec::new(),
            repositories: ArtifactRepositories::default(),
            request_timeout: Duration::from_secs(30),
            max_redirects: 5,
            max_deno_modules: 1_000,
            trust_local_input: false,
        }
    }
}

fn host_is_allowed(host: &str, allowed_hosts: &[String]) -> bool {
    allowed_hosts.iter().any(|allowed| {
        allowed == "*"
            || host == allowed
            || allowed.strip_prefix("*.").is_some_and(|suffix| {
                host.strip_suffix(suffix)
                    .is_some_and(|prefix| prefix.ends_with('.'))
            })
    })
}

#[async_trait]
pub trait Fetcher: Sync {
    async fn fetch(&self, dependency: Dependency, declared_from: PathBuf) -> Result<FetchMetadata>;
}

pub struct SourceFetcher {
    cache: PathBuf,
    policy: FetchPolicy,
    limits: EngineLimits,
    client: Option<Client>,
}

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
}

impl SourceFetcher {
    pub fn new(cache: PathBuf, policy: FetchPolicy, limits: EngineLimits) -> Result<Self> {
        fs::create_dir_all(&cache).map_err(|source| Error::Io {
            operation: "create cache directory".to_owned(),
            path: cache.clone(),
            source,
        })?;
        let cache = fs::canonicalize(&cache).map_err(|source| Error::Io {
            operation: "canonicalize cache directory".to_owned(),
            path: cache,
            source,
        })?;
        let client = Self::build_client(&policy).transpose()?;
        Ok(Self {
            cache,
            policy,
            limits,
            client,
        })
    }

    /// Fetches an explicitly requested remote package root.
    ///
    /// Unlike discovered dependencies, a remote root is intentionally allowed to
    /// resolve through its registry without a lockfile. Its discovered dependencies
    /// still use the normal fetch policy.
    pub async fn fetch_remote_root(&self, dependency: Dependency) -> Result<FetchMetadata> {
        let mut dependency = dependency;
        self.resolve_remote_root(&mut dependency).await?;

        if !dependency.is_resolved() {
            return Err(Error::Resolution {
                package: dependency.id(),
                message: "remote root has no resolved version and integrity".to_owned(),
            });
        }
        if let Some(cached) = self.cached(&dependency) {
            return Ok(cached);
        }

        self.fetch_remote_dependency(&dependency).await
    }
}

#[async_trait]
impl Fetcher for SourceFetcher {
    async fn fetch(&self, dependency: Dependency, declared_from: PathBuf) -> Result<FetchMetadata> {
        let mut dependency = dependency;
        self.resolve_unlocked_dependency(&mut dependency).await?;

        if dependency.is_local() {
            return self.fetch_local_dependency(&dependency, &declared_from);
        }
        if !dependency.is_resolved() {
            return Err(Error::Resolution {
                package: dependency.id(),
                message: "dependency has no locked version and integrity".to_owned(),
            });
        }
        if let Some(cached) = self.cached(&dependency) {
            return Ok(cached);
        }

        self.fetch_remote_dependency(&dependency).await
    }
}

impl SourceFetcher {
    async fn resolve_remote_root(&self, dependency: &mut Dependency) -> Result<()> {
        if dependency.is_resolved() {
            return Ok(());
        }

        match dependency.ecosystem {
            Ecosystem::Python => self.resolve_unlocked_python(dependency).await,
            Ecosystem::Npm => self.resolve_unlocked_npm(dependency).await,
            Ecosystem::Deno if dependency.requirement.starts_with("jsr:") => {
                self.resolve_unlocked_jsr(dependency).await
            }
            Ecosystem::Deno => Err(Error::Resolution {
                package: dependency.id(),
                message: "unsupported remote root source".to_owned(),
            }),
        }
    }

    async fn resolve_unlocked_dependency(&self, dependency: &mut Dependency) -> Result<()> {
        if dependency.is_local() || dependency.is_resolved() || !self.policy.allow_unlocked {
            return Ok(());
        }

        match dependency.ecosystem {
            Ecosystem::Python => self.resolve_unlocked_python(dependency).await,
            Ecosystem::Npm => self.resolve_unlocked_npm(dependency).await,
            Ecosystem::Deno if dependency.requirement.starts_with("npm:") => {
                self.resolve_unlocked_npm(dependency).await
            }
            Ecosystem::Deno if dependency.requirement.starts_with("jsr:") => {
                self.resolve_unlocked_jsr(dependency).await
            }
            Ecosystem::Deno => Ok(()),
        }
    }

    async fn fetch_remote_dependency(&self, dependency: &Dependency) -> Result<FetchMetadata> {
        let url = self.artifact_url(dependency).await?;
        let temporary = self.create_temporary_directory()?;
        let result = self
            .fetch_into_temporary(dependency, &url, &temporary)
            .await;
        if result.is_err() && temporary.exists() {
            let _ = fs::remove_dir_all(&temporary);
        }
        result
    }

    fn create_temporary_directory(&self) -> Result<PathBuf> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temporary = self.cache.join(format!(
            ".tmp-{}-{nonce}-{}",
            std::process::id(),
            TEMPORARY_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&temporary).map_err(|source| Error::Io {
            operation: "create temporary cache entry".to_owned(),
            path: temporary.clone(),
            source,
        })?;
        Ok(temporary)
    }

    async fn fetch_into_temporary(
        &self,
        dependency: &Dependency,
        url: &url::Url,
        temporary: &Path,
    ) -> Result<FetchMetadata> {
        if dependency.is_pinned_github() {
            return self.fetch_github_archive(dependency, url, temporary).await;
        }

        match dependency.ecosystem {
            Ecosystem::Npm => self.fetch_npm_package(dependency, url, temporary).await,
            Ecosystem::Python => self.fetch_python_package(dependency, url, temporary).await,
            Ecosystem::Deno => self.fetch_deno_package(dependency, url, temporary).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::host_is_allowed;

    #[test]
    fn all_hosts_glob_allows_any_host() {
        assert!(host_is_allowed("example.com", &["*".to_owned()]));
        assert!(host_is_allowed("sub.example.com", &["*".to_owned()]));
    }

    #[test]
    fn host_patterns_retain_existing_semantics() {
        assert!(host_is_allowed(
            "api.example.com",
            &["api.example.com".to_owned()]
        ));
        assert!(host_is_allowed(
            "api.example.com",
            &["*.example.com".to_owned()]
        ));
        assert!(!host_is_allowed(
            "example.com",
            &["*.example.com".to_owned()]
        ));
        assert!(!host_is_allowed(
            "notexample.com",
            &["*.example.com".to_owned()]
        ));
    }
}
