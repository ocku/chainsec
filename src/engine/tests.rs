use std::{
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;

use super::*;
use crate::{
    fetcher::Fetcher,
    model::{Dependency, FetchMetadata, PolicySummary, SerializableLimits},
};

fn engine_policy(
    limits: EngineLimits,
    require_lockfile: bool,
    offline: bool,
    allowed_hosts: Vec<String>,
    trust_local_input: bool,
    allow_insecure_http: bool,
) -> PolicySummary {
    PolicySummary {
        require_lockfile,
        offline,
        trust_local_input,
        allow_insecure_http,
        allowed_hosts,
        limits: SerializableLimits::from(&limits),
    }
}

struct NeverFetch;
#[async_trait]
impl Fetcher for NeverFetch {
    async fn fetch(
        &self,
        dependency: Dependency,
        _declared_from: PathBuf,
    ) -> Result<FetchMetadata> {
        panic!("unexpected fetch for {}", dependency.id())
    }
}

struct FixtureFetcher {
    packages: PathBuf,
}

#[async_trait]
impl Fetcher for FixtureFetcher {
    async fn fetch(
        &self,
        dependency: Dependency,
        _declared_from: PathBuf,
    ) -> Result<FetchMetadata> {
        Ok(FetchMetadata {
            source: self.packages.join(&dependency.name),
            package_id: dependency.id(),
            resolved_version: dependency.resolved_version.clone().unwrap(),
            digest: dependency.integrity.clone().unwrap(),
            source_url: dependency
                .source_url
                .unwrap_or_else(|| "https://fixtures.example.test/package.tar.gz".to_owned()),
            cache_hit: false,
        })
    }
}

struct CountingFixtureFetcher {
    packages: PathBuf,
    fetches: Arc<Mutex<HashMap<String, usize>>>,
}

struct ConcurrencyTrackingFixtureFetcher {
    packages: PathBuf,
    active_fetches: AtomicUsize,
    max_active_fetches: AtomicUsize,
}

impl ConcurrencyTrackingFixtureFetcher {
    fn new(packages: PathBuf) -> Self {
        Self {
            packages,
            active_fetches: AtomicUsize::new(0),
            max_active_fetches: AtomicUsize::new(0),
        }
    }

    fn max_active_fetches(&self) -> usize {
        self.max_active_fetches.load(Ordering::SeqCst)
    }
}

struct ContextFixtureFetcher {
    packages: PathBuf,
    fetches: Arc<Mutex<HashMap<String, usize>>>,
}

struct FailingFixtureFetcher {
    packages: PathBuf,
    failures: HashSet<String>,
    fetches: Arc<Mutex<HashMap<String, usize>>>,
}

#[async_trait]
impl Fetcher for CountingFixtureFetcher {
    fn prepare_fetch(
        &self,
        dependency: Dependency,
        declared_from: PathBuf,
    ) -> Result<crate::fetcher::PreparedFetch> {
        prepare_canonical_fixture_fetch(dependency, declared_from)
    }

    async fn fetch(
        &self,
        dependency: Dependency,
        _declared_from: PathBuf,
    ) -> Result<FetchMetadata> {
        *self
            .fetches
            .lock()
            .unwrap()
            .entry(dependency.id())
            .or_default() += 1;
        Ok(FetchMetadata {
            source: self.packages.join(&dependency.name),
            package_id: dependency.id(),
            resolved_version: dependency.resolved_version.clone().unwrap(),
            digest: dependency.integrity.clone().unwrap(),
            source_url: dependency
                .source_url
                .unwrap_or_else(|| "https://fixtures.example.test/package.tar.gz".to_owned()),
            cache_hit: false,
        })
    }
}

#[async_trait]
impl Fetcher for ConcurrencyTrackingFixtureFetcher {
    async fn fetch(
        &self,
        dependency: Dependency,
        _declared_from: PathBuf,
    ) -> Result<FetchMetadata> {
        let active_fetches = self.active_fetches.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_active_fetches
            .fetch_max(active_fetches, Ordering::SeqCst);

        for _ in 0..4 {
            tokio::task::yield_now().await;
        }

        self.active_fetches.fetch_sub(1, Ordering::SeqCst);
        Ok(FetchMetadata {
            source: self.packages.join(&dependency.name),
            package_id: dependency.id(),
            resolved_version: dependency.resolved_version.clone().unwrap(),
            digest: dependency.integrity.clone().unwrap(),
            source_url: dependency
                .source_url
                .unwrap_or_else(|| "https://fixtures.example.test/package.tar.gz".to_owned()),
            cache_hit: false,
        })
    }
}

#[async_trait]
impl Fetcher for FailingFixtureFetcher {
    async fn fetch(
        &self,
        dependency: Dependency,
        _declared_from: PathBuf,
    ) -> Result<FetchMetadata> {
        let package_id = dependency.id();
        *self
            .fetches
            .lock()
            .unwrap()
            .entry(package_id.clone())
            .or_default() += 1;
        if self.failures.contains(&dependency.name) {
            return Err(crate::Error::Fetch {
                package: package_id,
                source_url: "https://fixtures.example.test/failed-package.tgz".to_owned(),
                message: "fixture fetch failure".to_owned(),
            });
        }
        Ok(FetchMetadata {
            source: self.packages.join(&dependency.name),
            package_id,
            resolved_version: dependency.resolved_version.clone().unwrap(),
            digest: dependency.integrity.clone().unwrap(),
            source_url: dependency
                .source_url
                .unwrap_or_else(|| "https://fixtures.example.test/package.tar.gz".to_owned()),
            cache_hit: false,
        })
    }
}

#[async_trait]
impl Fetcher for ContextFixtureFetcher {
    fn prepare_fetch(
        &self,
        dependency: Dependency,
        declared_from: PathBuf,
    ) -> Result<crate::fetcher::PreparedFetch> {
        prepare_canonical_fixture_fetch(dependency, declared_from)
    }

    async fn fetch(
        &self,
        dependency: Dependency,
        _declared_from: PathBuf,
    ) -> Result<FetchMetadata> {
        let package_id = dependency.id();
        *self
            .fetches
            .lock()
            .unwrap()
            .entry(package_id.clone())
            .or_default() += 1;
        let source = if dependency.name == "child" {
            self.packages.join(format!(
                "child-{}",
                dependency.resolved_version.as_deref().unwrap()
            ))
        } else {
            self.packages.join(&dependency.name)
        };
        Ok(FetchMetadata {
            source,
            package_id,
            resolved_version: dependency.resolved_version.clone().unwrap(),
            digest: dependency.integrity.clone().unwrap(),
            source_url: dependency.source_url.unwrap(),
            cache_hit: false,
        })
    }
}

struct SourceUrlPolicyFetcher {
    package: PathBuf,
    denied_url: String,
    fetches: Arc<Mutex<Vec<String>>>,
}

struct DenoLockfilePolicyFetcher {
    package: PathBuf,
    fetches: Arc<Mutex<Vec<PathBuf>>>,
}

struct DenoNpmRequirementFetcher {
    packages: PathBuf,
    fetches: Arc<Mutex<Vec<String>>>,
}

fn fetched_fixture_root(source: PathBuf, package_id: &str) -> FetchMetadata {
    FetchMetadata {
        source,
        package_id: package_id.to_owned(),
        resolved_version: "1.0.0".to_owned(),
        digest: format!("sha512-{package_id}"),
        source_url: format!("https://roots.example.test/{package_id}.tgz"),
        cache_hit: false,
    }
}

fn prepare_canonical_fixture_fetch(
    dependency: Dependency,
    declared_from: PathBuf,
) -> Result<crate::fetcher::PreparedFetch> {
    let deno_lockfile_identity = dependency
        .deno_lockfile_snapshot
        .as_ref()
        .map(|snapshot| snapshot.identity())
        .unwrap_or_default();
    let acquisition_identity = format!(
        "{}\0{}\0{deno_lockfile_identity}",
        dependency.id(),
        dependency.source_url.as_deref().unwrap_or_default(),
    );
    let mut prepared =
        <NeverFetch as Fetcher>::prepare_fetch(&NeverFetch, dependency, declared_from)?;
    prepared.acquisition_identity = Some(acquisition_identity);
    Ok(prepared)
}

#[async_trait]
impl Fetcher for SourceUrlPolicyFetcher {
    fn prepare_fetch(
        &self,
        dependency: Dependency,
        declared_from: PathBuf,
    ) -> Result<crate::fetcher::PreparedFetch> {
        prepare_canonical_fixture_fetch(dependency, declared_from)
    }

    async fn fetch(
        &self,
        dependency: Dependency,
        _declared_from: PathBuf,
    ) -> Result<FetchMetadata> {
        let source_url = dependency.source_url.clone().unwrap();
        self.fetches.lock().unwrap().push(source_url.clone());
        if source_url == self.denied_url {
            return Err(crate::error::Error::Policy {
                operation: "test dependency fetch".to_owned(),
                message: source_url,
            });
        }

        Ok(FetchMetadata {
            source: self.package.clone(),
            package_id: dependency.id(),
            resolved_version: dependency.resolved_version.unwrap(),
            digest: dependency.integrity.unwrap(),
            source_url,
            cache_hit: false,
        })
    }
}

#[async_trait]
impl Fetcher for DenoLockfilePolicyFetcher {
    async fn fetch(
        &self,
        dependency: Dependency,
        _declared_from: PathBuf,
    ) -> Result<FetchMetadata> {
        let lockfile = dependency.lockfile.clone().unwrap();
        self.fetches.lock().unwrap().push(lockfile.clone());
        let lockfile_contents = fs::read_to_string(&lockfile).unwrap();
        if lockfile_contents.contains(r#""decision":"deny""#) {
            return Err(crate::error::Error::Policy {
                operation: "test Deno lockfile verification".to_owned(),
                message: lockfile.display().to_string(),
            });
        }

        Ok(FetchMetadata {
            source: self.package.clone(),
            package_id: dependency.id(),
            resolved_version: dependency.resolved_version.unwrap(),
            digest: dependency.integrity.unwrap(),
            source_url: dependency.source_url.unwrap(),
            cache_hit: false,
        })
    }
}

#[async_trait]
impl Fetcher for DenoNpmRequirementFetcher {
    async fn fetch(
        &self,
        dependency: Dependency,
        _declared_from: PathBuf,
    ) -> Result<FetchMetadata> {
        self.fetches
            .lock()
            .unwrap()
            .push(dependency.requirement.clone());
        assert_eq!(dependency.resolved_version.as_deref(), Some("1.0.0"));
        assert!(dependency.integrity.is_none());

        let package = dependency
            .requirement
            .strip_prefix("npm:")
            .and_then(|specifier| specifier.rsplit_once('@'))
            .map(|(package, _)| package)
            .unwrap()
            .to_owned();
        Ok(FetchMetadata {
            source: self.packages.join(&package),
            package_id: format!("npm:{package}@1.0.0#sha512-{package}"),
            resolved_version: "1.0.0".to_owned(),
            digest: format!("sha512-{package}"),
            source_url: format!("https://registry.example.test/{package}.tgz"),
            cache_hit: false,
        })
    }
}

mod batch_core;
mod cycles;
mod deno_sharing;
mod frontier;
mod limits;
mod lock_resolution;
mod policy;
mod source_identity;

#[test]
fn analysis_thread_count_is_clamped_to_safe_bounds() {
    let rules = [];
    let fetcher = NeverFetch;
    let engine = Engine::new(
        &rules,
        &fetcher,
        engine_policy(
            crate::model::EngineLimits::default(),
            true,
            true,
            Vec::new(),
            false,
            false,
        ),
    )
    .with_max_analysis_threads(usize::MAX);
    assert_eq!(engine.max_analysis_threads, 64);

    let engine = engine.with_max_analysis_threads(0);
    assert_eq!(engine.max_analysis_threads, 1);
}
