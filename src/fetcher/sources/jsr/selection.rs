use std::str::FromStr;

use node_semver::{Range as NpmRange, Version as NpmVersion};
use serde_json::Value as JsonValue;

use crate::{
    error::{Error, Result},
    model::Dependency,
};

pub(super) fn jsr_package_and_requirement(dependency: &Dependency) -> Result<(&str, &str)> {
    let specifier =
        dependency
            .requirement
            .strip_prefix("jsr:")
            .ok_or_else(|| Error::Resolution {
                package: dependency.id(),
                message: "JSR dependency must begin with jsr:".to_owned(),
            })?;
    match specifier.rsplit_once('@') {
        Some((package, requirement)) if !package.is_empty() => Ok((package, requirement)),
        _ if !specifier.is_empty() => Ok((specifier, "*")),
        _ => Err(Error::Resolution {
            package: dependency.id(),
            message: "JSR dependency has no package name".to_owned(),
        }),
    }
}

pub(super) fn select_jsr_version(
    dependency: &Dependency,
    requirement: &str,
    metadata: &JsonValue,
) -> Result<String> {
    let versions = jsr_releases(dependency, metadata)?;
    let range = NpmRange::from_str(requirement).map_err(|_| Error::Resolution {
        package: dependency.id(),
        message: format!("invalid JSR version requirement {requirement}"),
    })?;
    versions
        .iter()
        .filter(|(_, release)| !jsr_release_is_yanked(release))
        .filter_map(|(raw_version, _)| {
            let version = NpmVersion::from_str(raw_version).ok()?;
            range.satisfies(&version).then_some(version)
        })
        .max()
        .map(|version| version.to_string())
        .ok_or_else(|| Error::Resolution {
            package: dependency.id(),
            message: format!("JSR registry has no release satisfying {requirement}"),
        })
}

pub(super) fn jsr_compare_versions(
    dependency: &Dependency,
    from: &str,
    to: &str,
    metadata: &JsonValue,
) -> Result<Vec<String>> {
    let versions = jsr_releases(dependency, metadata)?;
    validate_jsr_endpoints(dependency, from, to, versions)?;
    Ok(vec![to.to_owned(), from.to_owned()])
}

pub(super) fn jsr_range_versions(
    dependency: &Dependency,
    from: &str,
    to: &str,
    metadata: &JsonValue,
) -> Result<Vec<String>> {
    let versions = jsr_releases(dependency, metadata)?;
    let (from_version, to_version) = validate_jsr_endpoints(dependency, from, to, versions)?;
    let mut selected = versions
        .iter()
        .filter(|(_, release)| !jsr_release_is_yanked(release))
        .filter_map(|(raw_version, _)| {
            let version = NpmVersion::from_str(raw_version).ok()?;
            (version >= from_version && version <= to_version)
                .then_some((version, raw_version.clone()))
        })
        .collect::<Vec<_>>();
    selected.sort_unstable_by(|(left, _), (right, _)| right.cmp(left));
    Ok(selected
        .into_iter()
        .map(|(_, raw_version)| raw_version)
        .collect())
}

pub(super) fn jsr_versions_at_or_below(
    dependency: &Dependency,
    selected: &str,
    metadata: &JsonValue,
) -> Result<Vec<String>> {
    let selected_version = NpmVersion::from_str(selected).map_err(|_| Error::Resolution {
        package: dependency.id(),
        message: "resolved JSR release is not a semantic version".to_owned(),
    })?;
    let versions = jsr_releases(dependency, metadata)?;
    let mut older = versions
        .iter()
        .filter(|(_, release)| !jsr_release_is_yanked(release))
        .filter_map(|(raw_version, _)| {
            let version = NpmVersion::from_str(raw_version).ok()?;
            (version < selected_version).then_some(version)
        })
        .collect::<Vec<_>>();
    older.sort_unstable_by(|left, right| right.cmp(left));

    let mut ordered = Vec::with_capacity(older.len() + 1);
    ordered.push(selected.to_owned());
    ordered.extend(older.into_iter().map(|version| version.to_string()));
    Ok(ordered)
}

fn jsr_releases<'a>(
    dependency: &Dependency,
    metadata: &'a JsonValue,
) -> Result<&'a serde_json::Map<String, JsonValue>> {
    metadata
        .get("versions")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| Error::Resolution {
            package: dependency.id(),
            message: "JSR registry response has no versions".to_owned(),
        })
}

fn validate_jsr_endpoints(
    dependency: &Dependency,
    from: &str,
    to: &str,
    versions: &serde_json::Map<String, JsonValue>,
) -> Result<(NpmVersion, NpmVersion)> {
    let from_version = jsr_endpoint_version(dependency, "FROM", from, versions)?;
    let to_version = jsr_endpoint_version(dependency, "TO", to, versions)?;
    if from_version == to_version {
        return Err(Error::Resolution {
            package: dependency.id(),
            message: format!("JSR FROM and TO endpoints must be distinct: {from}"),
        });
    }
    if from_version > to_version {
        return Err(Error::Resolution {
            package: dependency.id(),
            message: format!("JSR FROM endpoint {from} must be older than TO endpoint {to}"),
        });
    }
    Ok((from_version, to_version))
}

fn jsr_endpoint_version(
    dependency: &Dependency,
    endpoint: &str,
    raw_version: &str,
    versions: &serde_json::Map<String, JsonValue>,
) -> Result<NpmVersion> {
    let version = NpmVersion::from_str(raw_version).map_err(|_| Error::Resolution {
        package: dependency.id(),
        message: format!("JSR {endpoint} endpoint {raw_version} is not a semantic version"),
    })?;
    let release = versions.get(raw_version).ok_or_else(|| Error::Resolution {
        package: dependency.id(),
        message: format!("JSR {endpoint} endpoint {raw_version} is not published"),
    })?;
    if jsr_release_is_yanked(release) {
        return Err(Error::Resolution {
            package: dependency.id(),
            message: format!("JSR {endpoint} endpoint {raw_version} is yanked"),
        });
    }
    Ok(version)
}

fn jsr_release_is_yanked(release: &JsonValue) -> bool {
    release
        .get("yanked")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false)
}
