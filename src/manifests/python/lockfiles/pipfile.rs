use std::{collections::HashSet, path::Path};

use serde_json::Value as JsonValue;

use super::artifact::valid_sha256_integrity;
use crate::{
    error::Result,
    manifests::{
        python::matching::{JsonPackageIndex, find_json_package, normalize},
        shared::{manifest_error, read},
    },
    model::Dependency,
};

#[cfg(test)]
pub(super) fn enrich(path: &Path, dependencies: &mut Vec<Dependency>) -> Result<()> {
    enrich_bounded(path, dependencies, usize::MAX)
}

pub(super) fn enrich_bounded(
    path: &Path,
    dependencies: &mut Vec<Dependency>,
    max_packages: usize,
) -> Result<()> {
    let value: JsonValue =
        serde_json::from_str(&read(path)?).map_err(|error| manifest_error(path, error))?;
    let root = value
        .as_object()
        .ok_or_else(|| manifest_error(path, "Pipfile.lock root must be an object"))?;
    if root
        .get("_meta")
        .and_then(JsonValue::as_object)
        .and_then(|metadata| metadata.get("pipfile-spec"))
        .and_then(JsonValue::as_u64)
        != Some(6)
    {
        return Err(manifest_error(
            path,
            "Pipfile.lock must have supported integer pipfile-spec 6",
        ));
    }
    if !root.contains_key("default") && !root.contains_key("develop") {
        return Err(manifest_error(
            path,
            "Pipfile.lock must contain default or develop",
        ));
    }
    for section in ["default", "develop"] {
        if let Some(entries) = root.get(section) {
            entries.as_object().ok_or_else(|| {
                manifest_error(path, format!("Pipfile.lock {section} must be an object"))
            })?;
        }
    }

    let mut index = JsonPackageIndex::new();
    let mut seen = HashSet::new();
    for section in ["default", "develop"] {
        let Some(entries) = root.get(section).and_then(JsonValue::as_object) else {
            continue;
        };
        for (name, entry) in entries {
            let normalized = normalize(name);
            if seen.insert((normalized.clone(), entry)) {
                index.entry(normalized).or_default().push(entry);
            }
        }
    }

    let declared = std::mem::take(dependencies);
    let mut enriched = Vec::with_capacity(declared.len().min(max_packages));
    for mut dependency in declared {
        if enriched.len() >= max_packages {
            return Err(crate::error::Error::LimitExceeded {
                resource: "manifest dependencies".to_owned(),
                limit: u64::try_from(max_packages).unwrap_or(u64::MAX),
            });
        }
        let entry = find_json_package(path, &index, &dependency)?;
        let Some(entry) = entry else {
            enriched.push(dependency);
            continue;
        };
        dependency.lockfile = Some(path.to_owned());
        if dependency.is_pinned_github() {
            enriched.push(dependency);
            continue;
        }

        let version = entry
            .get("version")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| {
                manifest_error(
                    path,
                    format!(
                        "Pipfile.lock entry for {} has no string version",
                        dependency.name
                    ),
                )
            })?
            .trim_start_matches("==")
            .to_owned();
        dependency.resolved_version = Some(version);
        let direct_source = dependency.source_url.is_some();
        if let Some(hashes) = entry.get("hashes") {
            let hashes = hashes.as_array().ok_or_else(|| {
                manifest_error(
                    path,
                    format!(
                        "Pipfile.lock hashes for {} must be an array",
                        dependency.name
                    ),
                )
            })?;

            if !hashes.iter().all(JsonValue::is_string) {
                return Err(manifest_error(
                    path,
                    format!(
                        "Pipfile.lock hashes for {} must be strings",
                        dependency.name
                    ),
                ));
            }
            let authorized = hashes
                .iter()
                .filter_map(JsonValue::as_str)
                .filter(|hash| valid_sha256_integrity(hash))
                .collect::<Vec<_>>();
            if authorized.is_empty() {
                if direct_source {
                    dependency.resolved_version = None;
                } else if hashes.is_empty() {
                    dependency.registry_integrity_required = true;
                } else {
                    return Err(manifest_error(
                        path,
                        format!(
                            "Pipfile.lock hashes for {} contain no supported SHA-256 digest",
                            dependency.name
                        ),
                    ));
                }
                enriched.push(dependency);
            } else if direct_source {
                dependency.integrity = Some(authorized.join(" "));
                enriched.push(dependency);
            } else {
                let remaining = max_packages.saturating_sub(enriched.len());
                if authorized.len() > remaining {
                    return Err(crate::error::Error::LimitExceeded {
                        resource: "manifest dependencies".to_owned(),
                        limit: u64::try_from(max_packages).unwrap_or(u64::MAX),
                    });
                }
                for hash in authorized {
                    let mut artifact = dependency.clone();
                    artifact.integrity = Some(hash.to_owned());
                    enriched.push(artifact);
                }
            }
        } else {
            if direct_source {
                dependency.resolved_version = None;
            } else {
                dependency.registry_integrity_required = true;
            }
            enriched.push(dependency);
        }
    }
    *dependencies = enriched;
    Ok(())
}
