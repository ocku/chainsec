use std::{path::Path, str::FromStr};

use node_semver::{Range as NpmRange, Version as NpmVersion};
use serde_json::Value as JsonValue;
use url::Url;

use crate::{
    error::{Error, Result},
    model::{Dependency, Ecosystem, FetchMetadata},
};

use crate::fetcher::SourceFetcher;

impl SourceFetcher {
    pub(in crate::fetcher) async fn fetch_npm_package(
        &self,
        dependency: &Dependency,
        url: &Url,
        temporary: &Path,
    ) -> Result<FetchMetadata> {
        self.fetch_standalone_archive(dependency, url, temporary)
            .await
    }

    pub(in crate::fetcher) async fn resolve_unlocked_npm(
        &self,
        dependency: &mut Dependency,
    ) -> Result<()> {
        let (package, requirement) = npm_package_and_requirement(dependency);
        let api = self.policy.repositories.npm_metadata_url(&package)?;
        let metadata: JsonValue =
            serde_json::from_slice(&self.download(&api).await?).map_err(|error| {
                Error::Resolution {
                    package: dependency.id(),
                    message: format!("invalid npm registry response: {error}"),
                }
            })?;
        resolve_npm_release(dependency, requirement, &metadata)
    }

    pub(in crate::fetcher) async fn npm_artifact_url(
        &self,
        dependency: &Dependency,
    ) -> Result<Url> {
        let version = dependency
            .resolved_version
            .as_deref()
            .ok_or_else(|| Error::Resolution {
                package: dependency.id(),
                message: "npm dependency has no locked version".to_owned(),
            })?;
        let (package, _) = npm_package_and_requirement(dependency);
        let api = self.policy.repositories.npm_metadata_url(&package)?;
        let metadata: JsonValue =
            serde_json::from_slice(&self.download(&api).await?).map_err(|error| {
                Error::Resolution {
                    package: dependency.id(),
                    message: format!("invalid npm registry response: {error}"),
                }
            })?;
        npm_tarball_url(dependency, version, &metadata)
    }
}

pub(in crate::fetcher) fn npm_package_and_requirement(dependency: &Dependency) -> (String, String) {
    let raw = if dependency.ecosystem == Ecosystem::Deno {
        dependency
            .requirement
            .strip_prefix("npm:")
            .unwrap_or(&dependency.requirement)
    } else if dependency.requirement.starts_with("npm:") {
        dependency.requirement.trim_start_matches("npm:")
    } else {
        return (dependency.name.clone(), dependency.requirement.clone());
    };
    match raw.rsplit_once('@') {
        Some((name, requirement)) if !name.is_empty() => (name.to_owned(), requirement.to_owned()),
        _ => (raw.to_owned(), "*".to_owned()),
    }
}

pub(in crate::fetcher) fn npm_tarball_url(
    dependency: &Dependency,
    version: &str,
    metadata: &JsonValue,
) -> Result<Url> {
    let tarball = metadata
        .get("versions")
        .and_then(|versions| versions.get(version))
        .and_then(|release| release.get("dist"))
        .and_then(|dist| dist.get("tarball"))
        .and_then(JsonValue::as_str)
        .ok_or_else(|| Error::Resolution {
            package: dependency.id(),
            message: format!("npm registry has no tarball URL for locked release {version}"),
        })?;
    Url::parse(tarball).map_err(|error| Error::Resolution {
        package: dependency.id(),
        message: format!("invalid npm tarball URL: {error}"),
    })
}

pub(in crate::fetcher) fn resolve_npm_release(
    dependency: &mut Dependency,
    requirement: String,
    metadata: &JsonValue,
) -> Result<()> {
    let versions = metadata
        .get("versions")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| Error::Resolution {
            package: dependency.id(),
            message: "npm registry response has no versions".to_owned(),
        })?;
    let range = NpmRange::from_str(&requirement).ok();
    let tagged_version = range.is_none().then(|| {
        metadata
            .get("dist-tags")
            .and_then(|tags| tags.get(&requirement))
            .and_then(JsonValue::as_str)
    });
    let selected = if let Some(range) = range {
        versions
            .iter()
            .filter_map(|(raw_version, release)| {
                let version = NpmVersion::from_str(raw_version).ok()?;
                range.satisfies(&version).then_some((version, release))
            })
            .max_by(|(left, _), (right, _)| left.cmp(right))
            .map(|(version, release)| (version.to_string(), release))
    } else {
        tagged_version.flatten().and_then(|version| {
            versions
                .get(version)
                .map(|release| (version.to_owned(), release))
        })
    }
    .ok_or_else(|| Error::Resolution {
        package: dependency.id(),
        message: format!("npm registry has no release satisfying {requirement}"),
    })?;

    let dist = selected.1.get("dist").ok_or_else(|| Error::Resolution {
        package: dependency.id(),
        message: format!("npm release {} has no distribution metadata", selected.0),
    })?;
    let tarball = dist
        .get("tarball")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| Error::Resolution {
            package: dependency.id(),
            message: format!("npm release {} has no tarball URL", selected.0),
        })?;
    let integrity = dist
        .get("integrity")
        .and_then(JsonValue::as_str)
        .filter(|integrity| integrity.starts_with("sha256-") || integrity.starts_with("sha512-"))
        .ok_or_else(|| Error::Resolution {
            package: dependency.id(),
            message: format!(
                "npm release {} has no supported SHA-256 or SHA-512 integrity",
                selected.0
            ),
        })?;
    dependency.resolved_version = Some(selected.0);
    dependency.source_url = Some(tarball.to_owned());
    dependency.integrity = Some(integrity.to_owned());
    Ok(())
}
