use std::{collections::BTreeMap, str::FromStr};

use pep440_rs::Version;

use crate::{error::Result, fetcher::SourceFetcher, model::Dependency};

use super::{
    metadata::{
        PyPiArtifact, PyPiMetadata, pin_python_release, python_releases, select_source_distribution,
    },
    resolution_error,
};

impl SourceFetcher {
    pub(super) fn python_versions_at_or_below(
        &self,
        selected: Dependency,
        count: usize,
        metadata: &PyPiMetadata,
    ) -> Result<Vec<Dependency>> {
        let selected_version = selected
            .resolved_version
            .as_deref()
            .and_then(|version| Version::from_str(version).ok())
            .ok_or_else(|| {
                resolution_error(&selected, "resolved PyPI release is not a PEP 440 version")
            })?;
        let releases = python_releases(&selected, metadata)?;
        let mut older = Vec::new();
        for (raw_version, artifacts) in releases {
            let Ok(version) = Version::from_str(raw_version) else {
                continue;
            };
            if version < selected_version {
                self.enforce_remote_version_candidate_limit(older.len() + 2)?;
                older.push((version, raw_version, artifacts));
            }
        }
        older.sort_unstable_by(|(left, ..), (right, ..)| right.cmp(left));

        self.enforce_remote_version_candidate_limit(1)?;
        let mut resolved = vec![selected.clone()];
        self.enforce_remote_version_limit(resolved.len())?;
        if resolved.len() == count {
            return Ok(resolved);
        }
        for (_, version, artifacts) in older {
            if let Some(artifact) = select_source_distribution(artifacts) {
                let mut dependency = selected.clone();
                pin_python_release(&mut dependency, version, artifact);
                resolved.push(dependency);
                self.enforce_remote_version_limit(resolved.len())?;
                if resolved.len() == count {
                    break;
                }
            }
        }
        Ok(resolved)
    }

    pub(super) fn python_range_versions(
        &self,
        dependency: &Dependency,
        from: &str,
        to: &str,
        metadata: &PyPiMetadata,
    ) -> Result<Vec<Dependency>> {
        let releases = python_releases(dependency, metadata)?;
        let (from_version, to_version) = validate_python_endpoints(dependency, from, to, releases)?;
        let from_artifact = python_endpoint_artifact(dependency, "FROM", from, releases)?;
        let to_artifact = python_endpoint_artifact(dependency, "TO", to, releases)?;

        let mut from_dependency = dependency.clone();
        pin_python_release(&mut from_dependency, from, from_artifact);
        let mut to_dependency = dependency.clone();
        pin_python_release(&mut to_dependency, to, to_artifact);

        let mut candidates = Vec::new();
        for (raw_version, artifacts) in releases {
            let Ok(version) = Version::from_str(raw_version) else {
                continue;
            };
            if version >= from_version && version <= to_version {
                self.enforce_remote_version_candidate_limit(candidates.len() + 1)?;
                candidates.push((version, raw_version, artifacts));
            }
        }
        candidates.sort_unstable_by(|(left, ..), (right, ..)| right.cmp(left));

        let mut resolved = Vec::new();
        for (_, raw_version, artifacts) in candidates {
            if raw_version == to {
                resolved.push(to_dependency.clone());
            } else if raw_version == from {
                resolved.push(from_dependency.clone());
            } else if let Some(artifact) = select_source_distribution(artifacts) {
                let mut candidate = dependency.clone();
                pin_python_release(&mut candidate, raw_version, artifact);
                resolved.push(candidate);
            }
            self.enforce_remote_version_limit(resolved.len())?;
        }
        Ok(resolved)
    }
}

pub(super) fn python_compare_versions(
    dependency: &Dependency,
    from: &str,
    to: &str,
    metadata: &PyPiMetadata,
) -> Result<Vec<Dependency>> {
    let releases = python_releases(dependency, metadata)?;
    validate_python_endpoints(dependency, from, to, releases)?;
    let from_artifact = python_endpoint_artifact(dependency, "FROM", from, releases)?;
    let to_artifact = python_endpoint_artifact(dependency, "TO", to, releases)?;

    let mut to_dependency = dependency.clone();
    pin_python_release(&mut to_dependency, to, to_artifact);
    let mut from_dependency = dependency.clone();
    pin_python_release(&mut from_dependency, from, from_artifact);
    Ok(vec![to_dependency, from_dependency])
}

fn validate_python_endpoints(
    dependency: &Dependency,
    from: &str,
    to: &str,
    releases: &BTreeMap<String, Vec<PyPiArtifact>>,
) -> Result<(Version, Version)> {
    let from_version = python_endpoint_version(dependency, "FROM", from, releases)?;
    let to_version = python_endpoint_version(dependency, "TO", to, releases)?;
    if from_version == to_version {
        return Err(resolution_error(
            dependency,
            format!("PyPI FROM and TO endpoints must be distinct: {from}"),
        ));
    }
    if from_version > to_version {
        return Err(resolution_error(
            dependency,
            format!("PyPI FROM endpoint {from} must be older than TO endpoint {to}"),
        ));
    }
    Ok((from_version, to_version))
}

fn python_endpoint_version(
    dependency: &Dependency,
    endpoint: &str,
    raw_version: &str,
    releases: &BTreeMap<String, Vec<PyPiArtifact>>,
) -> Result<Version> {
    let version = Version::from_str(raw_version).map_err(|error| {
        resolution_error(
            dependency,
            format!("PyPI {endpoint} endpoint {raw_version} is not a PEP 440 version: {error}"),
        )
    })?;
    if !releases.contains_key(raw_version) {
        return Err(resolution_error(
            dependency,
            format!("PyPI {endpoint} endpoint {raw_version} is not published"),
        ));
    }
    Ok(version)
}

fn python_endpoint_artifact<'a>(
    dependency: &Dependency,
    endpoint: &str,
    raw_version: &str,
    releases: &'a BTreeMap<String, Vec<PyPiArtifact>>,
) -> Result<&'a PyPiArtifact> {
    releases
        .get(raw_version)
        .and_then(|artifacts| select_source_distribution(artifacts))
        .ok_or_else(|| {
            resolution_error(
                dependency,
                format!(
                    "PyPI {endpoint} endpoint {raw_version} has no pullable non-yanked source distribution with a SHA-256 digest"
                ),
            )
        })
}
