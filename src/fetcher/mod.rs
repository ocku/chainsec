mod archive;
mod cache;
mod deno;
mod integrity;
mod network;

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use reqwest::{blocking::Client, redirect::Policy};
use sha2::{Digest, Sha256};

use crate::{
    error::{Error, Result},
    model::{Dependency, Ecosystem, EngineLimits, FetchMetadata},
};

use self::{
    archive::{extract, single_root_or_self},
    integrity::verify_integrity,
};

static TEMPORARY_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct FetchPolicy {
    pub offline: bool,
    pub allow_unlocked: bool,
    pub allowed_hosts: Vec<String>,
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
pub trait SourceFetcher: Sync {
    async fn fetch(&self, dependency: Dependency, declared_from: PathBuf) -> Result<FetchMetadata>;
}

pub struct SafeSourceFetcher {
    cache: PathBuf,
    policy: FetchPolicy,
    limits: EngineLimits,
    client: Option<Client>,
}

impl SafeSourceFetcher {
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
        let client = if policy.offline {
            None
        } else {
            let redirects = policy.max_redirects;
            let redirect_hosts = policy.allowed_hosts.clone();
            let request_timeout = policy.request_timeout;
            // reqwest's blocking client creates a private Tokio runtime. Construct it
            // outside the caller's runtime so its setup never blocks an async worker.
            let client = std::thread::spawn(move || {
                Client::builder()
                    .timeout(request_timeout)
                    .no_proxy()
                    .redirect(Policy::custom(move |attempt| {
                        let url = attempt.url();
                        let allowed = matches!(url.scheme(), "http" | "https")
                            && url
                                .host_str()
                                .is_some_and(|host| host_is_allowed(host, &redirect_hosts));
                        if !allowed {
                            attempt.error("redirect target is not allowed by network policy")
                        } else if attempt.previous().len() >= redirects {
                            attempt.error("redirect limit exceeded")
                        } else {
                            attempt.follow()
                        }
                    }))
                    .user_agent(concat!("chainsec/", env!("CARGO_PKG_VERSION")))
                    .build()
            })
            .join()
            .map_err(|_| Error::InvalidConfiguration {
                message: "HTTP client builder thread panicked".to_owned(),
            })?
            .map_err(|error| Error::InvalidConfiguration {
                message: error.to_string(),
            })?;
            Some(client)
        };
        Ok(Self {
            cache,
            policy,
            limits,
            client,
        })
    }
}

impl Drop for SafeSourceFetcher {
    fn drop(&mut self) {
        if let Some(client) = self.client.take() {
            // reqwest's blocking client owns an internal runtime, which must not
            // be dropped from a Tokio worker thread.
            let _ = std::thread::spawn(move || drop(client)).join();
        }
    }
}

#[async_trait]
impl SourceFetcher for SafeSourceFetcher {
    async fn fetch(&self, dependency: Dependency, declared_from: PathBuf) -> Result<FetchMetadata> {
        let package = dependency.id();
        let source_url = dependency
            .source_url
            .clone()
            .unwrap_or_else(|| dependency.requirement.clone());
        let worker = self.clone_for_worker();
        tokio::task::spawn_blocking(move || worker.fetch_blocking(&dependency, &declared_from))
            .await
            .map_err(|error| Error::Fetch {
                package,
                source_url,
                message: format!("fetch worker failed: {error}"),
            })?
    }
}

impl SafeSourceFetcher {
    fn clone_for_worker(&self) -> Self {
        Self {
            cache: self.cache.clone(),
            policy: self.policy.clone(),
            limits: self.limits.clone(),
            client: self.client.clone(),
        }
    }

    fn fetch_blocking(
        &self,
        dependency: &Dependency,
        declared_from: &Path,
    ) -> Result<FetchMetadata> {
        let mut dependency = dependency.clone();
        self.resolve_unlocked_dependency(&mut dependency)?;

        if dependency.is_local() {
            return self.fetch_local_dependency(&dependency, declared_from);
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

        self.fetch_remote_dependency(&dependency)
    }

    fn resolve_unlocked_dependency(&self, dependency: &mut Dependency) -> Result<()> {
        if dependency.is_local()
            || dependency.is_resolved()
            || !self.policy.allow_unlocked
            || dependency.source_url.is_some()
        {
            return Ok(());
        }

        match dependency.ecosystem {
            Ecosystem::Python => self.resolve_unlocked_python(dependency),
            Ecosystem::Npm => self.resolve_unlocked_npm(dependency),
            Ecosystem::Deno if dependency.requirement.starts_with("npm:") => {
                self.resolve_unlocked_npm(dependency)
            }
            Ecosystem::Deno => Ok(()),
        }
    }

    fn fetch_local_dependency(
        &self,
        dependency: &Dependency,
        declared_from: &Path,
    ) -> Result<FetchMetadata> {
        let raw_path = local_dependency_path(dependency)?;
        let candidate = if raw_path.is_absolute() {
            raw_path.clone()
        } else {
            declared_from.join(&raw_path)
        };
        let source = fs::canonicalize(&candidate).map_err(|source| Error::Io {
            operation: "canonicalize local dependency".to_owned(),
            path: candidate,
            source,
        })?;
        let declaring_root = fs::canonicalize(declared_from).map_err(|source| Error::Io {
            operation: "canonicalize declaring package".to_owned(),
            path: declared_from.to_owned(),
            source,
        })?;
        if !self.policy.trust_local_input && !source.starts_with(&declaring_root) {
            return Err(Error::Policy {
                operation: "local dependency".to_owned(),
                message: format!(
                    "{} escapes {}; use --trust-local-input to allow it",
                    source.display(),
                    declaring_root.display()
                ),
            });
        }

        Ok(FetchMetadata {
            source,
            package_id: dependency.id(),
            resolved_version: dependency
                .resolved_version
                .clone()
                .unwrap_or_else(|| "local".to_owned()),
            digest: "local-unverified".to_owned(),
            source_url: format!("file:{}", raw_path.display()),
            cache_hit: false,
        })
    }

    fn fetch_remote_dependency(&self, dependency: &Dependency) -> Result<FetchMetadata> {
        let url = self.artifact_url(dependency)?;
        let temporary = self.create_temporary_directory()?;
        let result = self.fetch_into_temporary(dependency, &url, &temporary);
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

    fn fetch_into_temporary(
        &self,
        dependency: &Dependency,
        url: &url::Url,
        temporary: &Path,
    ) -> Result<FetchMetadata> {
        if dependency.ecosystem == Ecosystem::Deno && dependency.requirement.starts_with("jsr:") {
            let (source, digest, stats) =
                self.fetch_jsr_package(url, temporary, dependency.integrity.as_deref())?;
            return self.publish(dependency, url, digest, temporary, &source, stats);
        }
        if dependency.ecosystem == Ecosystem::Deno
            && matches!(url.scheme(), "http" | "https")
            && !url.path().ends_with(".tgz")
        {
            let (source, digest, stats) = self.fetch_deno_graph(
                url,
                temporary,
                dependency.integrity.as_deref(),
                dependency.lockfile.as_deref(),
            )?;
            return self.publish(dependency, url, digest, temporary, &source, stats);
        }

        let bytes = self.download(url)?;
        if !dependency.is_pinned_github() {
            verify_integrity(&bytes, dependency.integrity.as_deref(), url.as_str())?;
        }
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        let source = temporary.join("source");
        fs::create_dir(&source).map_err(|source_error| Error::Io {
            operation: "create extraction directory".to_owned(),
            path: source.clone(),
            source: source_error,
        })?;
        let archive_name = if dependency.is_pinned_github() {
            "git.tar.gz"
        } else {
            url.path()
        };
        let stats = extract(&bytes, archive_name, &source, &self.limits)?;
        let package_root = single_root_or_self(&source)?;
        self.publish(dependency, url, digest, temporary, &package_root, stats)
    }
}

fn local_dependency_path(dependency: &Dependency) -> Result<PathBuf> {
    if let Some(source_url) = dependency
        .source_url
        .as_deref()
        .filter(|url| url.starts_with("file:"))
    {
        let url = url::Url::parse(source_url).map_err(|error| Error::Resolution {
            package: dependency.id(),
            message: format!("invalid local dependency URL: {error}"),
        })?;
        return url.to_file_path().map_err(|()| Error::Resolution {
            package: dependency.id(),
            message: "local dependency URL is not a valid filesystem path".to_owned(),
        });
    }

    Ok(PathBuf::from(
        dependency
            .requirement
            .strip_prefix("file:")
            .unwrap_or(&dependency.requirement),
    ))
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
