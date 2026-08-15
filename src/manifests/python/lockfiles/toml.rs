use std::path::Path;

use super::{
    artifact::{expand_file_artifacts_bounded, valid_sha256_integrity},
    common::{LockSchema, enrich_toml_packages},
    package_string,
};
use crate::{error::Result, manifests::shared::manifest_error, model::Dependency};

#[cfg(test)]
pub(super) fn enrich_poetry(path: &Path, dependencies: &mut Vec<Dependency>) -> Result<()> {
    enrich_poetry_bounded(path, dependencies, usize::MAX)
}

pub(super) fn enrich_poetry_bounded(
    path: &Path,
    dependencies: &mut Vec<Dependency>,
    max_packages: usize,
) -> Result<()> {
    enrich_toml_packages(
        path,
        dependencies,
        max_packages,
        LockSchema::Poetry,
        |dependency, package, remaining| {
            if dependency.is_pinned_github() {
                return Ok(vec![dependency.clone()]);
            }
            let mut locked = dependency.clone();
            locked.resolved_version = package_string(package, "version");
            expand_file_artifacts_bounded(path, &locked, package, remaining)
        },
    )
}

#[cfg(test)]
pub(super) fn enrich_uv(path: &Path, dependencies: &mut Vec<Dependency>) -> Result<()> {
    enrich_uv_bounded(path, dependencies, usize::MAX)
}

pub(super) fn enrich_uv_bounded(
    path: &Path,
    dependencies: &mut Vec<Dependency>,
    max_packages: usize,
) -> Result<()> {
    enrich_toml_packages(
        path,
        dependencies,
        max_packages,
        LockSchema::Uv,
        |dependency, package, remaining| {
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

            if !direct_source && artifacts.len() > remaining {
                return Err(crate::error::Error::LimitExceeded {
                    resource: "manifest dependencies".to_owned(),
                    limit: u64::try_from(remaining).unwrap_or(u64::MAX),
                });
            }
            let mut expanded = Vec::with_capacity(artifacts.len().min(remaining.max(1)));
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
        },
    )
}

#[cfg(test)]
pub(super) fn enrich_pdm(path: &Path, dependencies: &mut Vec<Dependency>) -> Result<()> {
    enrich_pdm_bounded(path, dependencies, usize::MAX)
}

pub(super) fn enrich_pdm_bounded(
    path: &Path,
    dependencies: &mut Vec<Dependency>,
    max_packages: usize,
) -> Result<()> {
    enrich_toml_packages(
        path,
        dependencies,
        max_packages,
        LockSchema::Pdm,
        |dependency, package, remaining| {
            if dependency.is_pinned_github() {
                return Ok(vec![dependency.clone()]);
            }
            let mut locked = dependency.clone();
            locked.resolved_version = package_string(package, "version");
            expand_file_artifacts_bounded(path, &locked, package, remaining)
        },
    )
}
