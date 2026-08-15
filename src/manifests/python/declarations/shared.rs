use std::path::Path;

use toml::Value as TomlValue;

use super::super::matching::normalize;
use crate::{
    error::Result,
    manifests::shared::{github_archive, manifest_error, read},
    model::{Dependency, Ecosystem},
};

pub(super) fn parse_toml(path: &Path) -> Result<TomlValue> {
    let text = read(path)?;
    toml::from_str(&text).map_err(|error| manifest_error(path, error))
}

pub(in crate::manifests::python) fn dependency_from_requirement(requirement: &str) -> Dependency {
    let before_marker = requirement.split(';').next().unwrap_or(requirement).trim();
    let name = before_marker
        .split(['<', '>', '=', '!', '~', '[', ' ', '@'])
        .next()
        .unwrap_or(before_marker)
        .trim();
    let canonical_name = normalize(name);
    let canonical_requirement = requirement.strip_prefix(name).map_or_else(
        || requirement.to_owned(),
        |suffix| format!("{canonical_name}{suffix}"),
    );
    let canonical_source_requirement = before_marker.strip_prefix(name).map_or_else(
        || before_marker.to_owned(),
        |suffix| format!("{canonical_name}{suffix}"),
    );
    let mut dependency = declared_dependency(
        &canonical_name,
        &canonical_requirement,
        &canonical_source_requirement,
    );
    if dependency.source_url.is_none()
        && let Some((_, url)) = before_marker.split_once('@')
    {
        dependency.source_url = Some(url.trim().to_owned());
    }
    dependency
}

pub(super) fn declared_dependency(
    name: &str,
    requirement: &str,
    source_requirement: &str,
) -> Dependency {
    let mut dependency = Dependency::declared(Ecosystem::Python, normalize(name), requirement);
    if let Some((archive, commit)) = github_archive(source_requirement) {
        dependency.resolved_version = Some(commit);
        dependency.source_url = Some(archive);
    }
    dependency
}
