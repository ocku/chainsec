use std::{fmt, path::PathBuf};

use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Dependency {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub requirement: String,
    pub resolved_version: Option<String>,
    pub source_url: Option<String>,
    pub integrity: Option<String>,
    pub lockfile: Option<PathBuf>,
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
        }
    }

    pub fn is_resolved(&self) -> bool {
        self.is_local()
            || (self.resolved_version.is_some()
                && (self.integrity.is_some() || self.is_pinned_github()))
    }

    pub fn is_pinned_github(&self) -> bool {
        let Some(revision) = self.resolved_version.as_deref() else {
            return false;
        };

        revision.len() == 40
            && revision.bytes().all(|byte| byte.is_ascii_hexdigit())
            && self.source_url.as_deref().is_some_and(|url| {
                url.starts_with("https://codeload.github.com/")
                    && url.contains("/tar.gz/")
                    && url.ends_with(revision)
            })
    }

    pub fn is_local(&self) -> bool {
        self.requirement.starts_with("file:")
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
