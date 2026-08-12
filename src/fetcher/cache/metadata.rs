use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::model::{Dependency, FetchMetadata};

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct CacheMetadata {
    package_id: String,
    resolved_version: String,
    integrity: Option<String>,
    digest: String,
    pub(super) source_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) effective_source_url: Option<String>,

    fetcher_version: String,
}

impl CacheMetadata {
    pub(super) fn matches_dependency(&self, dependency: &Dependency) -> bool {
        self.matches_identity(dependency) && self.matches_source(dependency)
    }

    fn matches_identity(&self, dependency: &Dependency) -> bool {
        let expected_version = dependency
            .resolved_version
            .as_deref()
            .unwrap_or(&dependency.requirement);

        self.package_id == dependency.id()
            && self.resolved_version == expected_version
            && self.integrity.as_deref() == dependency.integrity.as_deref()
            && self.fetcher_version == env!("CARGO_PKG_VERSION")
    }

    fn matches_source(&self, dependency: &Dependency) -> bool {
        valid_source_url(&self.source_url)
            && dependency
                .source_url
                .as_deref()
                .is_none_or(|source_url| source_url == self.source_url)
    }

    pub(super) fn new(dependency: &Dependency, source_url: &Url, digest: String) -> Self {
        Self {
            package_id: dependency.id(),
            resolved_version: dependency
                .resolved_version
                .clone()
                .unwrap_or_else(|| dependency.requirement.clone()),
            integrity: dependency.integrity.clone(),
            digest,
            source_url: source_url.to_string(),
            effective_source_url: None,

            fetcher_version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    pub(super) fn with_effective_source_url(mut self, effective_source_url: Option<&Url>) -> Self {
        self.effective_source_url = effective_source_url.map(Url::to_string);
        self
    }

    pub(super) fn into_fetch_metadata(self, source: PathBuf, cache_hit: bool) -> FetchMetadata {
        FetchMetadata {
            source,
            package_id: self.package_id,
            resolved_version: self.resolved_version,
            digest: self.digest,
            source_url: self.source_url,
            cache_hit,
        }
    }
}

fn valid_source_url(source_url: &str) -> bool {
    !source_url.is_empty()
        && Url::parse(source_url)
            .ok()
            .is_some_and(|url| matches!(url.scheme(), "http" | "https"))
}
