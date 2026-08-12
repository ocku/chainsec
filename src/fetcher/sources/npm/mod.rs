use std::str::FromStr;

use node_semver::{Range as NpmRange, Version as NpmVersion};
use serde_json::Value as JsonValue;
use url::Url;

use crate::{
    error::{Error, Result},
    model::{Dependency, Ecosystem},
};

use crate::fetcher::{RemoteVersionSelection, SourceFetcher, integrity::supported_npm_integrity};

impl SourceFetcher {
    #[allow(dead_code)]
    pub(in crate::fetcher) async fn resolve_unlocked_npm(
        &self,
        dependency: &mut Dependency,
    ) -> Result<()> {
        let mut budget = self.network_budget();
        self.resolve_unlocked_npm_with_budget(dependency, &mut budget)
            .await
    }

    pub(in crate::fetcher) async fn resolve_unlocked_npm_with_budget(
        &self,
        dependency: &mut Dependency,
        budget: &mut crate::fetcher::network::NetworkBudget,
    ) -> Result<()> {
        let (package, requirement) = npm_package_and_requirement(dependency);
        let metadata = self
            .npm_metadata_with_budget(dependency, &package, budget)
            .await?;
        if let Some(version) = dependency.resolved_version.clone() {
            let release = metadata
                .get("versions")
                .and_then(JsonValue::as_object)
                .and_then(|versions| versions.get(&version))
                .ok_or_else(|| Error::Resolution {
                    package: dependency.id(),
                    message: format!("npm registry has no locked release {version}"),
                })?;
            pin_npm_release(dependency, version, release)
        } else {
            resolve_npm_release(dependency, requirement, &metadata)
        }
    }

    #[allow(dead_code)]
    pub(in crate::fetcher) async fn resolve_npm_version_selection(
        &self,
        dependency: Dependency,
        selection: RemoteVersionSelection,
    ) -> Result<Vec<Dependency>> {
        let mut budget = self.network_budget();
        self.resolve_npm_version_selection_with_budget(dependency, selection, &mut budget)
            .await
    }

    pub(in crate::fetcher) async fn resolve_npm_version_selection_with_budget(
        &self,
        dependency: Dependency,
        selection: RemoteVersionSelection,
        budget: &mut crate::fetcher::network::NetworkBudget,
    ) -> Result<Vec<Dependency>> {
        let (package, requirement) = npm_package_and_requirement(&dependency);
        let metadata = self
            .npm_metadata_with_budget(&dependency, &package, budget)
            .await?;
        match selection {
            RemoteVersionSelection::Last(count) => {
                let selected = select_npm_release(&dependency, &requirement, &metadata)?;
                self.npm_versions_at_or_below(&dependency, selected, count, &metadata)
            }
            RemoteVersionSelection::Compare { from, to } => {
                npm_compare_versions(&dependency, &from, &to, &metadata)
            }
            RemoteVersionSelection::Range { from, to } => {
                self.npm_range_versions(&dependency, &from, &to, &metadata)
            }
        }
    }

    #[allow(dead_code)]
    pub(in crate::fetcher) async fn npm_artifact_url(
        &self,
        dependency: &Dependency,
    ) -> Result<Url> {
        let mut budget = self.network_budget();
        self.npm_artifact_url_with_budget(dependency, &mut budget)
            .await
    }

    pub(in crate::fetcher) async fn npm_artifact_url_with_budget(
        &self,
        dependency: &Dependency,
        budget: &mut crate::fetcher::network::NetworkBudget,
    ) -> Result<Url> {
        // Standard npm lockfiles pin the artifact URL. Honor that binding instead
        // of re-resolving it through registry metadata. Deno `npm:` entries use
        // their configured registry metadata endpoint by design.
        if dependency.ecosystem == Ecosystem::Npm
            && let Some(url) = locked_npm_artifact_url(dependency)?
        {
            return Ok(url);
        }

        let version = dependency
            .resolved_version
            .as_deref()
            .ok_or_else(|| Error::Resolution {
                package: dependency.id(),
                message: "npm dependency has no locked version".to_owned(),
            })?;
        let (package, _) = npm_package_and_requirement(dependency);
        let metadata = self
            .npm_metadata_with_budget(dependency, &package, budget)
            .await?;
        npm_tarball_url(dependency, version, &metadata)
    }

    #[allow(dead_code)]
    async fn npm_metadata(&self, dependency: &Dependency, package: &str) -> Result<JsonValue> {
        let mut budget = self.network_budget();
        self.npm_metadata_with_budget(dependency, package, &mut budget)
            .await
    }

    async fn npm_metadata_with_budget(
        &self,
        dependency: &Dependency,
        package: &str,
        budget: &mut crate::fetcher::network::NetworkBudget,
    ) -> Result<JsonValue> {
        let api = self.policy.repositories.npm_metadata_url(package)?;
        serde_json::from_slice(&self.download_with_budget(&api, true, budget).await?).map_err(
            |error| Error::Resolution {
                package: dependency.id(),
                message: format!("invalid npm registry response: {error}"),
            },
        )
    }
}

fn npm_package_and_requirement(dependency: &Dependency) -> (String, String) {
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

fn locked_npm_artifact_url(dependency: &Dependency) -> Result<Option<Url>> {
    dependency
        .source_url
        .as_deref()
        .map(|url| {
            Url::parse(url).map_err(|error| Error::Resolution {
                package: dependency.id(),
                message: format!("invalid locked npm tarball URL: {error}"),
            })
        })
        .transpose()
}

fn npm_tarball_url(dependency: &Dependency, version: &str, metadata: &JsonValue) -> Result<Url> {
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

fn resolve_npm_release(
    dependency: &mut Dependency,
    requirement: String,
    metadata: &JsonValue,
) -> Result<()> {
    let selected = select_npm_release(dependency, &requirement, metadata)?;
    pin_npm_release(dependency, selected.0, selected.1)
}

fn select_npm_release<'a>(
    dependency: &Dependency,
    requirement: &str,
    metadata: &'a JsonValue,
) -> Result<(String, &'a JsonValue)> {
    let versions = metadata
        .get("versions")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| Error::Resolution {
            package: dependency.id(),
            message: "npm registry response has no versions".to_owned(),
        })?;
    let range = NpmRange::from_str(requirement).ok();
    let tagged_version = range.is_none().then(|| {
        metadata
            .get("dist-tags")
            .and_then(|tags| tags.get(requirement))
            .and_then(JsonValue::as_str)
    });
    let selected = if let Some(range) = range {
        versions
            .iter()
            .filter_map(|(raw_version, release)| {
                let version = NpmVersion::from_str(raw_version).ok()?;
                (range.satisfies(&version)
                    && !npm_release_is_yanked(release)
                    && npm_release_is_pullable(release))
                .then_some((version, release))
            })
            .max_by(|(left, _), (right, _)| left.cmp(right))
            .map(|(version, release)| (version.to_string(), release))
            .ok_or_else(|| Error::Resolution {
                package: dependency.id(),
                message: format!("npm registry has no release satisfying {requirement}"),
            })?
    } else if let Some(version) = tagged_version.flatten() {
        let release = versions.get(version).ok_or_else(|| Error::Resolution {
            package: dependency.id(),
            message: format!("npm registry has no release satisfying {requirement}"),
        })?;
        if npm_release_is_yanked(release) {
            return Err(Error::Resolution {
                package: dependency.id(),
                message: format!("npm dist-tag {requirement} targets yanked release {version}"),
            });
        }
        (version.to_owned(), release)
    } else {
        return Err(Error::Resolution {
            package: dependency.id(),
            message: format!("npm registry has no release satisfying {requirement}"),
        });
    };

    Ok(selected)
}

impl SourceFetcher {
    fn npm_versions_at_or_below(
        &self,
        dependency: &Dependency,
        selected: (String, &JsonValue),
        count: usize,
        metadata: &JsonValue,
    ) -> Result<Vec<Dependency>> {
        let selected_version =
            NpmVersion::from_str(&selected.0).map_err(|_| Error::Resolution {
                package: dependency.id(),
                message: "resolved npm release is not a semantic version".to_owned(),
            })?;
        let versions = metadata
            .get("versions")
            .and_then(JsonValue::as_object)
            .ok_or_else(|| Error::Resolution {
                package: dependency.id(),
                message: "npm registry response has no versions".to_owned(),
            })?;
        let mut older = Vec::new();
        for (raw_version, release) in versions {
            if npm_release_is_yanked(release) {
                continue;
            }
            let Ok(version) = NpmVersion::from_str(raw_version) else {
                continue;
            };
            if version < selected_version {
                self.enforce_remote_version_candidate_limit(older.len() + 2)?;
                older.push((version, release));
            }
        }
        older.sort_unstable_by(|(left, _), (right, _)| right.cmp(left));

        self.enforce_remote_version_candidate_limit(1)?;
        let mut candidates = Vec::new();
        candidates.push((selected_version, selected.0, selected.1));
        candidates.extend(
            older
                .into_iter()
                .map(|(version, release)| (version.clone(), version.to_string(), release)),
        );

        let mut resolved = Vec::new();
        for (_, version, release) in candidates {
            if npm_release_is_yanked(release) {
                continue;
            }
            let mut candidate = dependency.clone();
            if pin_npm_release(&mut candidate, version, release).is_ok() {
                resolved.push(candidate);
                self.enforce_remote_version_limit(resolved.len())?;
                if resolved.len() == count {
                    break;
                }
            }
        }
        Ok(resolved)
    }
}

fn npm_compare_versions(
    dependency: &Dependency,
    from: &str,
    to: &str,
    metadata: &JsonValue,
) -> Result<Vec<Dependency>> {
    let versions = npm_releases(dependency, metadata)?;
    validate_npm_endpoints(dependency, from, to, versions)?;

    let mut to_dependency = dependency.clone();
    pin_npm_release(
        &mut to_dependency,
        to.to_owned(),
        versions.get(to).expect("validated npm endpoint"),
    )?;
    let mut from_dependency = dependency.clone();
    pin_npm_release(
        &mut from_dependency,
        from.to_owned(),
        versions.get(from).expect("validated npm endpoint"),
    )?;
    Ok(vec![to_dependency, from_dependency])
}

impl SourceFetcher {
    fn npm_range_versions(
        &self,
        dependency: &Dependency,
        from: &str,
        to: &str,
        metadata: &JsonValue,
    ) -> Result<Vec<Dependency>> {
        let versions = npm_releases(dependency, metadata)?;
        let (from_version, to_version) = validate_npm_endpoints(dependency, from, to, versions)?;

        let mut from_dependency = dependency.clone();
        pin_npm_release(
            &mut from_dependency,
            from.to_owned(),
            versions.get(from).expect("validated npm endpoint"),
        )?;
        let mut to_dependency = dependency.clone();
        pin_npm_release(
            &mut to_dependency,
            to.to_owned(),
            versions.get(to).expect("validated npm endpoint"),
        )?;

        let mut candidates = Vec::new();
        for (raw_version, release) in versions {
            if npm_release_is_yanked(release) {
                continue;
            }
            let Ok(version) = NpmVersion::from_str(raw_version) else {
                continue;
            };
            if version >= from_version && version <= to_version {
                self.enforce_remote_version_candidate_limit(candidates.len() + 1)?;
                candidates.push((version, raw_version, release));
            }
        }
        candidates.sort_unstable_by(|(left, ..), (right, ..)| right.cmp(left));

        let mut resolved = Vec::new();
        for (_, raw_version, release) in candidates {
            if raw_version == to {
                resolved.push(to_dependency.clone());
            } else if raw_version == from {
                resolved.push(from_dependency.clone());
            } else {
                let mut candidate = dependency.clone();
                if pin_npm_release(&mut candidate, raw_version.clone(), release).is_ok() {
                    resolved.push(candidate);
                }
            }
            self.enforce_remote_version_limit(resolved.len())?;
        }
        Ok(resolved)
    }
}

fn npm_releases<'a>(
    dependency: &Dependency,
    metadata: &'a JsonValue,
) -> Result<&'a serde_json::Map<String, JsonValue>> {
    metadata
        .get("versions")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| Error::Resolution {
            package: dependency.id(),
            message: "npm registry response has no versions".to_owned(),
        })
}

fn validate_npm_endpoints(
    dependency: &Dependency,
    from: &str,
    to: &str,
    versions: &serde_json::Map<String, JsonValue>,
) -> Result<(NpmVersion, NpmVersion)> {
    let from_version = npm_endpoint_version(dependency, "FROM", from, versions)?;
    let to_version = npm_endpoint_version(dependency, "TO", to, versions)?;
    if from_version == to_version {
        return Err(Error::Resolution {
            package: dependency.id(),
            message: format!("npm FROM and TO endpoints must be distinct: {from}"),
        });
    }
    if from_version > to_version {
        return Err(Error::Resolution {
            package: dependency.id(),
            message: format!("npm FROM endpoint {from} must be older than TO endpoint {to}"),
        });
    }
    Ok((from_version, to_version))
}

fn npm_endpoint_version(
    dependency: &Dependency,
    endpoint: &str,
    raw_version: &str,
    versions: &serde_json::Map<String, JsonValue>,
) -> Result<NpmVersion> {
    let version = NpmVersion::from_str(raw_version).map_err(|_| Error::Resolution {
        package: dependency.id(),
        message: format!("npm {endpoint} endpoint {raw_version} is not a semantic version"),
    })?;
    let release = versions.get(raw_version).ok_or_else(|| Error::Resolution {
        package: dependency.id(),
        message: format!("npm {endpoint} endpoint {raw_version} is not published"),
    })?;
    if npm_release_is_yanked(release) {
        return Err(Error::Resolution {
            package: dependency.id(),
            message: format!("npm {endpoint} endpoint {raw_version} is yanked"),
        });
    }
    Ok(version)
}

fn npm_release_is_yanked(release: &JsonValue) -> bool {
    release
        .get("yanked")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false)
}

fn npm_release_is_pullable(release: &JsonValue) -> bool {
    let Some(dist) = release.get("dist") else {
        return false;
    };
    let Some(tarball) = dist.get("tarball").and_then(JsonValue::as_str) else {
        return false;
    };
    let Some(integrity) = dist.get("integrity").and_then(JsonValue::as_str) else {
        return false;
    };
    Url::parse(tarball).is_ok() && supported_npm_integrity(integrity)
}

fn pin_npm_release(
    dependency: &mut Dependency,
    version: String,
    release: &JsonValue,
) -> Result<()> {
    if npm_release_is_yanked(release) {
        return Err(Error::Resolution {
            package: dependency.id(),
            message: format!("npm release {version} is yanked"),
        });
    }
    let dist = release.get("dist").ok_or_else(|| Error::Resolution {
        package: dependency.id(),
        message: format!("npm release {version} has no distribution metadata"),
    })?;
    let tarball = dist
        .get("tarball")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| Error::Resolution {
            package: dependency.id(),
            message: format!("npm release {version} has no tarball URL"),
        })?;
    Url::parse(tarball).map_err(|error| Error::Resolution {
        package: dependency.id(),
        message: format!("npm release {version} has invalid tarball URL: {error}"),
    })?;
    let integrity = dist
        .get("integrity")
        .and_then(JsonValue::as_str)
        .filter(|integrity| supported_npm_integrity(integrity))
        .ok_or_else(|| Error::Resolution {
            package: dependency.id(),
            message: format!("npm release {version} has no supported SHA-256 or SHA-512 integrity"),
        })?;
    dependency.resolved_version = Some(version);
    dependency.source_url = Some(tarball.to_owned());
    dependency.integrity = Some(integrity.to_owned());
    Ok(())
}

#[cfg(test)]
mod tests;
