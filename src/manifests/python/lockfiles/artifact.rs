use std::path::Path;

use ::toml::Value as TomlValue;

use crate::{
    error::Result,
    manifests::shared::{is_sha256_integrity, manifest_error, optional_toml_string},
    model::Dependency,
};

#[cfg(test)]
pub(super) fn expand_file_artifacts(
    path: &Path,
    dependency: &Dependency,
    package: &TomlValue,
) -> Result<Vec<Dependency>> {
    expand_file_artifacts_bounded(path, dependency, package, usize::MAX)
}

pub(super) fn expand_file_artifacts_bounded(
    path: &Path,
    dependency: &Dependency,
    package: &TomlValue,
    remaining_packages: usize,
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

    if !direct_source && files.len() > remaining_packages {
        return Err(crate::error::Error::LimitExceeded {
            resource: "manifest dependencies".to_owned(),
            limit: u64::try_from(remaining_packages).unwrap_or(u64::MAX),
        });
    }
    let mut artifacts = Vec::with_capacity(files.len().min(remaining_packages.max(1)));
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
        if !is_sha256_integrity(hash) {
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
        artifact.source_url = optional_toml_string(
            path,
            table,
            "url",
            &format!("lockfile file {index} for {}", dependency.name),
        )?
        .map(str::to_owned)
        .or_else(|| dependency.source_url.clone());
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

pub(super) fn valid_sha256_integrity(value: &str) -> bool {
    is_sha256_integrity(value)
}

fn omit_unverified_artifact(dependency: &mut Dependency, direct_source: bool) {
    dependency.registry_integrity_required =
        !direct_source && dependency.resolved_version.is_some();
    if direct_source {
        dependency.resolved_version = None;
        dependency.integrity = None;
    }
}
