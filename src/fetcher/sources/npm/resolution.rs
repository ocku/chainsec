use std::str::FromStr;

use node_semver::{Range as NpmRange, Version as NpmVersion};
use serde_json::Value as JsonValue;
use url::Url;

use crate::{
    error::{Error, Result},
    fetcher::{RemoteVersionSelection, SourceFetcher, integrity::supported_npm_integrity},
    model::{Dependency, Ecosystem},
};

impl SourceFetcher {
    pub(in crate::fetcher) async fn resolve_unlocked_npm_with_budget(
        &self,
        dependency: &mut Dependency,
        budget: &mut crate::fetcher::network::NetworkBudget,
    ) -> Result<()> {
        let (package, requirement) = npm_package_and_requirement(dependency);
        validate_npm_registry_requirement(dependency, &requirement)?;
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

    pub(super) fn npm_versions_at_or_below(
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

    pub(super) fn npm_range_versions(
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

pub(super) fn npm_package_and_requirement(dependency: &Dependency) -> (String, String) {
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
    // `rsplit_once('@')` splits on the last `@`, so it correctly separates a
    // scoped package from a trailing version (`@scope/pkg@1.2.3`). For a scoped
    // package without a version (`@scope/pkg`), the split lands on the scope's
    // `@` and yields an empty name; the guard below intentionally treats that as
    // an unscoped specifier with a wildcard requirement rather than truncating
    // the package name.
    match raw.rsplit_once('@') {
        Some((name, requirement)) if !name.is_empty() => (name.to_owned(), requirement.to_owned()),
        _ => (raw.to_owned(), "*".to_owned()),
    }
}

/// Reject npm package specifiers that npm resolves without consulting the registry.
///
/// Direct tarballs and Git dependencies are legitimate `package.json` values, but
/// this fetcher can only analyze them once a lockfile has pinned an immutable
/// artifact URL and supported integrity value. Treating them as registry tags
/// would both misrepresent npm's resolution semantics and produce misleading
/// registry errors.
pub(super) fn validate_npm_registry_requirement(
    dependency: &Dependency,
    requirement: &str,
) -> Result<()> {
    if Url::parse(requirement)
        .ok()
        .is_some_and(|url| matches!(url.scheme(), "http" | "https"))
    {
        return Err(Error::Resolution {
            package: dependency.id(),
            message: "direct npm tarball dependencies require a lockfile integrity pin".to_owned(),
        });
    }

    if is_npm_git_requirement(requirement) {
        return Err(Error::Resolution {
            package: dependency.id(),
            message: "npm Git dependencies require a lockfile-resolved immutable source".to_owned(),
        });
    }

    Ok(())
}

fn is_npm_git_requirement(requirement: &str) -> bool {
    [
        "git+",
        "git://",
        "git@",
        "github:",
        "gist:",
        "bitbucket:",
        "gitlab:",
    ]
    .into_iter()
    .any(|prefix| requirement.starts_with(prefix))
        || (!requirement.starts_with('@')
            && requirement.matches('/').count() == 1
            && !requirement.starts_with('.')
            && !requirement.starts_with('~'))
}

pub(super) fn resolve_npm_release(
    dependency: &mut Dependency,
    requirement: String,
    metadata: &JsonValue,
) -> Result<()> {
    let selected = select_npm_release(dependency, &requirement, metadata)?;
    pin_npm_release(dependency, selected.0, selected.1)
}

pub(super) fn select_npm_release<'a>(
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
                (range.satisfies(&version) && npm_release_is_pullable(release))
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
        (version.to_owned(), release)
    } else {
        return Err(Error::Resolution {
            package: dependency.id(),
            message: format!("npm registry has no release satisfying {requirement}"),
        });
    };

    Ok(selected)
}

pub(super) fn npm_compare_versions(
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
    versions.get(raw_version).ok_or_else(|| Error::Resolution {
        package: dependency.id(),
        message: format!("npm {endpoint} endpoint {raw_version} is not published"),
    })?;
    Ok(version)
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

pub(super) fn pin_npm_release(
    dependency: &mut Dependency,
    version: String,
    release: &JsonValue,
) -> Result<()> {
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
