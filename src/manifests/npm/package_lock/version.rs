use std::str::FromStr;

use node_semver::{Range as NpmRange, Version as NpmVersion};
use serde_json::Value as JsonValue;

use crate::{
    manifests::shared::{github_archive, is_npm_dist_tag},
    model::Dependency,
};

pub(super) fn semver_satisfies(requirement: &str, version: &str) -> bool {
    NpmRange::from_str(requirement)
        .ok()
        .zip(NpmVersion::from_str(version).ok())
        .is_some_and(|(range, version)| range.satisfies(&version))
}

pub(super) fn locked_version_compatible(
    dependency: &Dependency,
    package: &JsonValue,
    local: bool,
) -> bool {
    if local || dependency.is_local() || github_archive(&dependency.requirement).is_some() {
        return true;
    }
    let requirement = dependency
        .requirement
        .strip_prefix("npm:")
        .and_then(|alias| alias.rsplit_once('@').map(|(_, requirement)| requirement))
        .unwrap_or(&dependency.requirement);
    let Some(version) = package
        .get("version")
        .and_then(JsonValue::as_str)
        .and_then(|version| NpmVersion::from_str(version).ok())
    else {
        return false;
    };

    match NpmRange::from_str(requirement) {
        Ok(range) => range.satisfies(&version),
        // The package-lock caller has already required exact equality with the
        // importer's selector; never use this exception for inferred mappings.
        Err(_) => is_npm_dist_tag(requirement),
    }
}
