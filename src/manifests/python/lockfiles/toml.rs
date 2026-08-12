use std::path::Path;

use super::{
    artifact::{MAX_LOCK_ARTIFACTS_PER_PACKAGE, expand_file_artifacts, valid_sha256_integrity},
    common::enrich_toml_packages,
    package_string,
};
use crate::{error::Result, manifests::shared::manifest_error, model::Dependency};

pub(super) fn enrich_poetry(path: &Path, dependencies: &mut Vec<Dependency>) -> Result<()> {
    enrich_toml_packages(path, dependencies, |dependency, package| {
        if dependency.is_pinned_github() {
            return Ok(vec![dependency.clone()]);
        }
        let mut locked = dependency.clone();
        locked.resolved_version = package_string(package, "version");
        expand_file_artifacts(path, &locked, package)
    })
}

pub(super) fn enrich_uv(path: &Path, dependencies: &mut Vec<Dependency>) -> Result<()> {
    enrich_toml_packages(path, dependencies, |dependency, package| {
        if dependency.is_pinned_github() {
            return Ok(vec![dependency.clone()]);
        }
        let direct_source = dependency.source_url.is_some() || dependency.is_local();
        let mut artifacts = Vec::new();
        if let Some(sdist) = package.get("sdist") {
            artifacts.push(sdist);
        }
        if let Some(wheels) = package.get("wheels") {
            let wheels = wheels.as_array().ok_or_else(|| {
                manifest_error(
                    path,
                    format!(
                        "uv lockfile wheels for {} must be an array",
                        dependency.name
                    ),
                )
            })?;
            artifacts.extend(wheels);
        }
        if artifacts.len() > MAX_LOCK_ARTIFACTS_PER_PACKAGE {
            return Err(manifest_error(
                path,
                format!(
                    "uv lockfile artifacts for {} exceeds the {MAX_LOCK_ARTIFACTS_PER_PACKAGE}-artifact limit",
                    dependency.name
                ),
            ));
        }
        if artifacts.is_empty() {
            let mut locked = dependency.clone();
            if direct_source {
                locked.resolved_version = None;
                locked.integrity = None;
            } else {
                locked.resolved_version = package_string(package, "version");
                locked.registry_integrity_required = locked.resolved_version.is_some();
            }
            return Ok(vec![locked]);
        }

        let mut expanded = Vec::with_capacity(artifacts.len());
        for (index, artifact) in artifacts.into_iter().enumerate() {
            let url = package_string(artifact, "url").ok_or_else(|| {
                manifest_error(
                    path,
                    format!(
                        "uv lockfile artifact {index} for {} has no string URL",
                        dependency.name
                    ),
                )
            })?;
            let integrity = package_string(artifact, "hash").ok_or_else(|| {
                manifest_error(
                    path,
                    format!(
                        "uv lockfile artifact {index} for {} has no string hash",
                        dependency.name
                    ),
                )
            })?;
            if !valid_sha256_integrity(&integrity) {
                return Err(manifest_error(
                    path,
                    format!(
                        "uv lockfile artifact for {} has an invalid SHA-256 hash",
                        dependency.name
                    ),
                ));
            }
            let mut locked = dependency.clone();
            locked.resolved_version = package_string(package, "version");
            locked.source_url = Some(url);
            locked.integrity = Some(integrity);
            expanded.push(locked);
        }
        if direct_source {
            let mut locked = dependency.clone();
            locked.resolved_version = package_string(package, "version");
            locked.integrity = Some(
                expanded
                    .iter()
                    .filter(|artifact| artifact.source_url == dependency.source_url)
                    .filter_map(|artifact| artifact.integrity.as_deref())
                    .collect::<Vec<_>>()
                    .join(" "),
            );
            if locked.integrity.as_deref() == Some("") {
                locked.resolved_version = None;
                locked.integrity = None;
            }
            return Ok(vec![locked]);
        }
        Ok(expanded)
    })
}

pub(super) fn enrich_pdm(path: &Path, dependencies: &mut Vec<Dependency>) -> Result<()> {
    enrich_toml_packages(path, dependencies, |dependency, package| {
        if dependency.is_pinned_github() {
            return Ok(vec![dependency.clone()]);
        }
        let mut locked = dependency.clone();
        locked.resolved_version = package_string(package, "version");
        expand_file_artifacts(path, &locked, package)
    })
}
