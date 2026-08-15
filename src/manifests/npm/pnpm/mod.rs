use std::{
    path::{Component, Path, PathBuf},
    str::FromStr,
};

use node_semver::{Range as NpmRange, Version as NpmVersion};
use serde_json::{Map, Value as JsonValue};

use crate::manifests::{
    npm::{github_archive_matches, local_source_url_from_directory, matching_github_archive},
    shared::{github_archive, manifest_error, optional_json_string, parse_bounded_yaml_json, read},
};
use crate::{
    error::Result,
    model::{Dependency, canonical_http_url},
};

pub(super) fn enrich(path: &Path, dependencies: &mut [Dependency]) -> Result<()> {
    enrich_importer(path, ".", dependencies)
}

pub(super) fn enrich_importer(
    path: &Path,
    importer_path: &str,
    dependencies: &mut [Dependency],
) -> Result<()> {
    let lockfile = yaml_json(path)?;
    let version = lockfile_version(path, &lockfile)?;
    validate_lock_fields(path, &lockfile)?;
    let Some(importer) = importer(&lockfile, importer_path) else {
        return Ok(());
    };
    let Some(importer_directory) = importer_directory(path, importer_path) else {
        return Ok(());
    };
    let packages = lockfile.get("packages").and_then(JsonValue::as_object);

    for dependency in dependencies {
        let Some((specifier, reference)) = locked_reference(importer, dependency) else {
            continue;
        };
        if specifier.is_some_and(|specifier| specifier != dependency.requirement) {
            continue;
        }

        enrich_dependency(
            dependency,
            reference,
            packages,
            &version,
            path,
            &importer_directory,
        );
    }
    Ok(())
}

fn lockfile_version(path: &Path, lockfile: &JsonValue) -> Result<String> {
    let version = lockfile
        .get("lockfileVersion")
        .and_then(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .or_else(|| value.as_f64().map(|version| version.to_string()))
        })
        .ok_or_else(|| manifest_error(path, "pnpm lockfileVersion is missing"))?;

    if matches!(version.as_str(), "5.3" | "5.4" | "6" | "6.0" | "9" | "9.0") {
        Ok(version)
    } else {
        Err(manifest_error(
            path,
            format!("unsupported pnpm lockfile version {version}"),
        ))
    }
}

fn validate_lock_fields(path: &Path, lockfile: &JsonValue) -> Result<()> {
    let root = lockfile
        .as_object()
        .ok_or_else(|| manifest_error(path, "pnpm lockfile root must be an object"))?;
    if let Some(importers) = root.get("importers") {
        let importers = importers
            .as_object()
            .ok_or_else(|| manifest_error(path, "pnpm importers must be an object"))?;
        for (importer_name, importer) in importers {
            let importer = importer.as_object().ok_or_else(|| {
                manifest_error(
                    path,
                    format!("pnpm importer {importer_name} must be an object"),
                )
            })?;
            for section in ["dependencies", "optionalDependencies", "devDependencies"] {
                let Some(entries) = importer.get(section) else {
                    continue;
                };
                let entries = entries.as_object().ok_or_else(|| {
                    manifest_error(
                        path,
                        format!("pnpm importer {importer_name} {section} must be an object"),
                    )
                })?;
                for (name, locked) in entries {
                    if locked.is_string() {
                        continue;
                    }
                    let locked = locked.as_object().ok_or_else(|| {
                        manifest_error(
                            path,
                            format!("pnpm locked reference for {name} must be a string or object"),
                        )
                    })?;
                    optional_json_string(
                        path,
                        locked,
                        "specifier",
                        &format!("pnpm locked reference for {name}"),
                    )?;
                    if optional_json_string(
                        path,
                        locked,
                        "version",
                        &format!("pnpm locked reference for {name}"),
                    )?
                    .is_none()
                    {
                        return Err(manifest_error(
                            path,
                            format!("pnpm locked reference for {name} version is missing"),
                        ));
                    }
                }
            }
        }
    }
    if let Some(packages) = root.get("packages") {
        let packages = packages
            .as_object()
            .ok_or_else(|| manifest_error(path, "pnpm packages must be an object"))?;
        for (key, package) in packages {
            let package = package.as_object().ok_or_else(|| {
                manifest_error(path, format!("pnpm package {key} must be an object"))
            })?;
            let resolution = match package.get("resolution") {
                Some(value) => value.as_object().ok_or_else(|| {
                    manifest_error(
                        path,
                        format!("pnpm package {key} resolution must be an object"),
                    )
                })?,
                None => package,
            };
            for field in ["integrity", "tarball"] {
                optional_json_string(
                    path,
                    resolution,
                    field,
                    &format!("pnpm package {key} resolution"),
                )?;
            }
        }
    }
    Ok(())
}

fn importer<'a>(lockfile: &'a JsonValue, importer_path: &str) -> Option<&'a JsonValue> {
    match lockfile.get("importers") {
        Some(importers) => importers.get(importer_path),
        None if importer_path == "." => Some(lockfile),
        None => None,
    }
}

fn importer_directory(lockfile: &Path, importer_path: &str) -> Option<PathBuf> {
    let root = lockfile.parent()?;
    if importer_path == "." {
        return Some(root.to_owned());
    }

    let importer = Path::new(importer_path);
    (!importer.as_os_str().is_empty()
        && !importer.is_absolute()
        && importer
            .components()
            .all(|component| matches!(component, Component::Normal(_))))
    .then(|| root.join(importer))
}

fn locked_reference<'a>(
    importer: &'a JsonValue,
    dependency: &Dependency,
) -> Option<(Option<&'a str>, &'a str)> {
    let locked = ["dependencies", "optionalDependencies", "devDependencies"]
        .into_iter()
        .find_map(|section| importer.get(section)?.get(&dependency.name))?;

    if let Some(reference) = locked.as_str() {
        let specifier = importer
            .get("specifiers")
            .and_then(|specifiers| specifiers.get(&dependency.name))
            .and_then(JsonValue::as_str);
        Some((specifier, reference))
    } else {
        Some((
            locked.get("specifier").and_then(JsonValue::as_str),
            locked.get("version").and_then(JsonValue::as_str)?,
        ))
    }
}

fn enrich_dependency(
    dependency: &mut Dependency,
    reference: &str,
    packages: Option<&Map<String, JsonValue>>,
    lockfile_version: &str,
    path: &Path,
    importer_directory: &Path,
) {
    if !github_archive_matches(dependency, Some(reference)) {
        return;
    }
    if let Some((archive, commit)) =
        github_archive(reference).or_else(|| matching_github_archive(dependency, Some(reference)))
    {
        dependency.resolved_version = Some(commit);
        dependency.source_url = Some(archive);
        dependency.lockfile = Some(path.to_owned());
        return;
    }
    if is_local_reference(reference) {
        if let Some(source_url) = local_source_url_from_directory(importer_directory, reference) {
            dependency.source_url = Some(source_url);
            dependency.lockfile = Some(path.to_owned());
        }
        return;
    }

    let Some((package_name, full_version)) = registry_reference(dependency, reference) else {
        return;
    };
    let version = bare_version(full_version);
    if !locked_version_compatible(dependency, version) {
        return;
    }
    let Some(package) = find_package(
        packages,
        package_name,
        full_version,
        version,
        lockfile_version,
    ) else {
        return;
    };
    let resolution = package.get("resolution").unwrap_or(package);
    let integrity = resolution
        .get("integrity")
        .and_then(JsonValue::as_str)
        .map(str::to_owned);

    dependency.resolved_version = Some(version.to_owned());
    dependency.integrity = integrity;
    dependency.source_url = registry_tarball(resolution);
    dependency.registry_integrity_required = dependency.source_url.is_none()
        && dependency.resolved_version.is_some()
        && dependency.integrity.is_none();
    dependency.lockfile = Some(path.to_owned());
}

fn is_local_reference(reference: &str) -> bool {
    ["link:", "workspace:", "file:"]
        .into_iter()
        .any(|prefix| reference.starts_with(prefix))
}

fn registry_reference<'a>(
    dependency: &'a Dependency,
    reference: &'a str,
) -> Option<(&'a str, &'a str)> {
    let declared_alias = dependency
        .requirement
        .strip_prefix("npm:")
        .and_then(parse_alias);
    if dependency.requirement.starts_with("npm:") && declared_alias.is_none() {
        return None;
    }

    let Some(locked_alias) = reference.strip_prefix("npm:") else {
        return declared_alias
            .is_none()
            .then_some((dependency.name.as_str(), reference));
    };
    let (locked_target, locked_version) = parse_alias(locked_alias)?;
    match declared_alias {
        Some((declared_target, _)) if declared_target == locked_target => {
            Some((locked_target, locked_version))
        }
        None if dependency.name == locked_target => Some((locked_target, locked_version)),
        None | Some(_) => None,
    }
}

fn parse_alias(alias: &str) -> Option<(&str, &str)> {
    let (target, requirement) = alias.rsplit_once('@')?;
    (!target.is_empty() && !requirement.is_empty() && valid_package_name(target))
        .then_some((target, requirement))
}

fn valid_package_name(name: &str) -> bool {
    if let Some(scoped) = name.strip_prefix('@') {
        let Some((scope, package)) = scoped.split_once('/') else {
            return false;
        };
        !scope.is_empty() && !package.is_empty() && !package.contains('/')
    } else {
        !name.is_empty() && !name.contains('@') && !name.contains('/')
    }
}

fn bare_version(reference: &str) -> &str {
    reference.split('(').next().unwrap_or(reference)
}

fn locked_version_compatible(dependency: &Dependency, version: &str) -> bool {
    let requirement = dependency
        .requirement
        .strip_prefix("npm:")
        .and_then(parse_alias)
        .map(|(_, requirement)| requirement)
        .unwrap_or(&dependency.requirement);
    let Ok(range) = NpmRange::from_str(requirement) else {
        return !dependency.requirement.starts_with("npm:");
    };
    NpmVersion::from_str(version).is_ok_and(|version| range.satisfies(&version))
}

fn find_package<'a>(
    packages: Option<&'a Map<String, JsonValue>>,
    name: &str,
    full_version: &str,
    version: &str,
    lockfile_version: &str,
) -> Option<&'a JsonValue> {
    let packages = packages?;
    package_keys(name, full_version, version, lockfile_version)
        .into_iter()
        .find_map(|key| packages.get(&key))
}

fn registry_tarball(resolution: &JsonValue) -> Option<String> {
    resolution
        .get("tarball")
        .and_then(JsonValue::as_str)
        .and_then(canonical_http_url)
}

fn yaml_json(path: &Path) -> Result<JsonValue> {
    parse_bounded_yaml_json(path, &read(path)?)
}

fn package_keys(
    name: &str,
    full_version: &str,
    version: &str,
    lockfile_version: &str,
) -> Vec<String> {
    if lockfile_version.starts_with('5') {
        vec![
            format!("/{name}/{full_version}"),
            format!("/{name}/{version}"),
        ]
    } else if lockfile_version.starts_with('6') {
        vec![
            format!("/{name}@{full_version}"),
            format!("/{name}@{version}"),
        ]
    } else {
        vec![
            format!("{name}@{full_version}"),
            format!("/{name}@{full_version}"),
            format!("{name}@{version}"),
            format!("/{name}@{version}"),
        ]
    }
}

#[cfg(test)]
mod tests;
