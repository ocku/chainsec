use std::{
    collections::HashMap,
    fmt,
    hash::{Hash, Hasher},
    path::PathBuf,
};

use sha2::{Digest, Sha256};

use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Python,
    Npm,
    Deno,
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Python => "python",
            Self::Npm => "npm",
            Self::Deno => "deno",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenoLockfileSnapshot {
    identity: String,
    remote_integrities: HashMap<String, String>,
}

impl Hash for DenoLockfileSnapshot {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.identity.hash(state);
        let mut entries = self.remote_integrities.iter().collect::<Vec<_>>();
        entries.sort_unstable();
        entries.hash(state);
    }
}

impl DenoLockfileSnapshot {
    pub(crate) fn from_lockfile(bytes: &[u8], value: &serde_json::Value) -> Self {
        let remote_integrities = deno_remote_integrity_entries(value)
            .map(|remote| {
                remote
                    .iter()
                    .filter_map(|(url, integrity)| {
                        let url = canonical_deno_remote_url(url)?;
                        integrity
                            .as_str()
                            .map(|integrity| (url, integrity.to_owned()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self {
            identity: format!("sha256:{}", hex::encode(Sha256::digest(bytes))),
            remote_integrities,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_remote_integrities(
        identity: impl Into<String>,
        remote_integrities: HashMap<String, String>,
    ) -> Self {
        Self {
            identity: identity.into(),
            remote_integrities,
        }
    }

    pub(crate) fn identity(&self) -> &str {
        &self.identity
    }

    pub(crate) fn remote_integrities(&self) -> &HashMap<String, String> {
        &self.remote_integrities
    }
}

fn deno_remote_integrity_entries(
    value: &serde_json::Value,
) -> Option<&serde_json::Map<String, serde_json::Value>> {
    if let Some(remote) = value.get("remote").and_then(serde_json::Value::as_object) {
        return Some(remote);
    }

    let root = value.as_object()?;
    (value.get("version").is_none()
        && !root.is_empty()
        && root.iter().all(|(url, integrity)| {
            canonical_deno_remote_url(url).is_some() && integrity.is_string()
        }))
    .then_some(root)
}

pub(crate) fn canonical_deno_remote_url(value: &str) -> Option<String> {
    Url::parse(value)
        .ok()
        .filter(|url| matches!(url.scheme(), "http" | "https"))
        .map(|url| url.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Dependency {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub requirement: String,
    pub resolved_version: Option<String>,
    pub source_url: Option<String>,
    pub integrity: Option<String>,
    pub lockfile: Option<PathBuf>,
    /// The validated Deno lockfile state captured during manifest discovery.
    #[serde(skip)]
    pub deno_lockfile_snapshot: Option<DenoLockfileSnapshot>,
    /// An exact registry version from a lockfile that lacks tarball integrity.
    /// The fetcher must obtain and verify the integrity from the configured registry.
    #[serde(skip)]
    pub registry_integrity_required: bool,
}

impl Dependency {
    pub fn declared(
        ecosystem: Ecosystem,
        name: impl Into<String>,
        requirement: impl Into<String>,
    ) -> Self {
        Self {
            ecosystem,
            name: name.into(),
            requirement: requirement.into(),
            resolved_version: None,
            source_url: None,
            integrity: None,
            lockfile: None,
            deno_lockfile_snapshot: None,
            registry_integrity_required: false,
        }
    }

    pub fn is_resolved(&self) -> bool {
        self.is_local()
            || (self.resolved_version.is_some()
                && (self.integrity.is_some() || self.is_pinned_github()))
    }

    pub fn requires_registry_integrity(&self) -> bool {
        self.registry_integrity_required
            && self.resolved_version.is_some()
            && self.integrity.is_none()
    }

    pub fn is_pinned_github(&self) -> bool {
        self.github_archive_url().is_some()
    }

    /// Returns the canonical codeload URL for a structurally valid GitHub commit archive.
    ///
    /// This deliberately accepts only GitHub's documented owner and repository character
    /// sets, which also excludes percent-encoded path-separator ambiguities.
    pub fn github_archive_url(&self) -> Option<Url> {
        let revision = self.resolved_version.as_deref()?;
        if !is_full_git_revision(revision) {
            return None;
        }

        let url = Url::parse(self.source_url.as_deref()?).ok()?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url
                .host_str()
                .is_none_or(|host| !host.eq_ignore_ascii_case("codeload.github.com"))
            || !matches!(url.port(), None | Some(443))
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path().contains('%')
        {
            return None;
        }

        let mut segments = url.path().split('/');
        let (Some(""), Some(owner), Some(repository), Some("tar.gz"), Some(url_revision), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return None;
        };
        if !is_github_owner(owner) || !is_github_repository(repository) || url_revision != revision
        {
            return None;
        }

        Url::parse(&format!(
            "https://codeload.github.com/{owner}/{repository}/tar.gz/{revision}"
        ))
        .ok()
    }

    pub fn is_local(&self) -> bool {
        ["file:", "link:", "portal:", "workspace:"]
            .into_iter()
            .any(|prefix| self.requirement.starts_with(prefix))
            || self.requirement.starts_with("./")
            || self.requirement.starts_with("../")
            || PathBuf::from(&self.requirement).is_absolute()
            || self
                .source_url
                .as_deref()
                .is_some_and(|url| url.starts_with("file:"))
    }

    pub fn id(&self) -> String {
        let version = self
            .resolved_version
            .as_deref()
            .unwrap_or(&self.requirement);
        let integrity = self.integrity.as_deref().unwrap_or("unverified");
        format!(
            "{}:{}@{}#{}",
            self.ecosystem,
            canonical_name(&self.ecosystem, &self.name),
            version,
            integrity
        )
    }
}

fn is_full_git_revision(revision: &str) -> bool {
    revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_github_owner(owner: &str) -> bool {
    !owner.is_empty()
        && owner
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn is_github_repository(repository: &str) -> bool {
    !repository.is_empty()
        && repository
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn canonical_name(ecosystem: &Ecosystem, name: &str) -> String {
    match ecosystem {
        Ecosystem::Python => name.to_ascii_lowercase().replace(['_', '.'], "-"),
        Ecosystem::Npm | Ecosystem::Deno => name.to_ascii_lowercase(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchMetadata {
    pub source: PathBuf,
    pub package_id: String,
    pub resolved_version: String,
    pub digest: String,
    pub source_url: String,
    pub cache_hit: bool,
}

#[cfg(test)]
mod tests;
