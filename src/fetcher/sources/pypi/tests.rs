use super::*;
use crate::{
    fetcher::{ArtifactRepositories, FetchPolicy},
    model::{Ecosystem, EngineLimits},
};

mod artifact_locked;
mod resolution;
mod url_policy;
mod versions;

fn dependency(requirement: &str) -> Dependency {
    Dependency::declared(Ecosystem::Python, "example", requirement)
}

fn test_fetcher(max_packages: usize) -> (tempfile::TempDir, SourceFetcher) {
    let temporary = tempfile::tempdir().unwrap();
    let limits = EngineLimits {
        max_packages,
        ..EngineLimits::default()
    };
    let fetcher = SourceFetcher::new(
        temporary.path().join("cache"),
        FetchPolicy::default(),
        limits,
    )
    .unwrap();
    (temporary, fetcher)
}
