use std::path::Path;

use ::toml::Value as TomlValue;

use super::common::package_string;
use crate::{error::Result, manifests::shared::manifest_error, model::Dependency};

pub(super) const MAX_LOCK_ARTIFACTS_PER_PACKAGE: usize = 1024;

pub(super) fn expand_file_artifacts(
    path: &Path,
    dependency: &Dependency,
    package: &TomlValue,
) -> Result<Vec<Dependency>> {
    let direct_source = dependency.source_url.is_some() && !dependency.is_pinned_github();
    let Some(files) = package.get("files") else {
        let mut dependency = dependency.clone();
        omit_unverified_artifact(&mut dependency, direct_source);
        return Ok(vec![dependency]);
    };
    let files = files.as_array().ok_or_else(|| {
        manifest_error(
            path,
            format!("lockfile files for {} must be an array", dependency.name),
        )
    })?;
    if files.is_empty() {
        let mut dependency = dependency.clone();
        omit_unverified_artifact(&mut dependency, direct_source);
        return Ok(vec![dependency]);
    }
    if files.len() > MAX_LOCK_ARTIFACTS_PER_PACKAGE {
        return Err(manifest_error(
            path,
            format!(
                "lockfile files for {} exceeds the {MAX_LOCK_ARTIFACTS_PER_PACKAGE}-artifact limit",
                dependency.name
            ),
        ));
    }

    let mut artifacts = Vec::with_capacity(files.len());
    for (index, file) in files.iter().enumerate() {
        let table = file.as_table().ok_or_else(|| {
            manifest_error(
                path,
                format!(
                    "lockfile file {index} for {} must be a table",
                    dependency.name
                ),
            )
        })?;
        let hash = table
            .get("hash")
            .and_then(TomlValue::as_str)
            .ok_or_else(|| {
                manifest_error(
                    path,
                    format!(
                        "lockfile file {index} for {} has no string hash",
                        dependency.name
                    ),
                )
            })?;
        if !valid_sha256_integrity(hash) {
            return Err(manifest_error(
                path,
                format!(
                    "lockfile file {index} for {} has an invalid SHA-256 hash",
                    dependency.name
                ),
            ));
        }
        if table.contains_key("file") && !table.get("file").is_some_and(TomlValue::is_str) {
            return Err(manifest_error(
                path,
                format!(
                    "lockfile file {index} for {} has a non-string filename",
                    dependency.name
                ),
            ));
        }

        let mut artifact = dependency.clone();
        artifact.integrity = Some(hash.to_owned());
        artifact.source_url = package_string(file, "url").or_else(|| dependency.source_url.clone());
        artifacts.push(artifact);
    }

    if direct_source {
        let mut direct = dependency.clone();
        direct.integrity = Some(
            artifacts
                .iter()
                .filter_map(|artifact| artifact.integrity.as_deref())
                .collect::<Vec<_>>()
                .join(" "),
        );
        return Ok(vec![direct]);
    }
    Ok(artifacts)
}

fn omit_unverified_artifact(dependency: &mut Dependency, direct_source: bool) {
    dependency.registry_integrity_required =
        !direct_source && dependency.resolved_version.is_some();
    if direct_source {
        dependency.resolved_version = None;
        dependency.integrity = None;
    }
}

pub(super) fn valid_sha256_integrity(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}
