use std::path::Path;

use serde_json::Value as JsonValue;

use super::super::shared::{github_archive, manifest_error, read};
use crate::{error::Result, model::Dependency};

pub(super) fn enrich(path: &Path, dependencies: &mut [Dependency]) -> Result<()> {
    let value = yaml_json(path)?;
    let version = value
        .get("lockfileVersion")
        .and_then(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .or_else(|| value.as_f64().map(|v| v.to_string()))
        })
        .ok_or_else(|| manifest_error(path, "pnpm lockfileVersion is missing"))?;
    if !matches!(version.as_str(), "5.3" | "5.4" | "6" | "6.0" | "9" | "9.0") {
        return Err(manifest_error(
            path,
            format!("unsupported pnpm lockfile version {version}"),
        ));
    }
    let importer = value
        .get("importers")
        .and_then(|value| value.get("."))
        .unwrap_or(&value);
    let packages = value.get("packages").and_then(JsonValue::as_object);
    for dependency in dependencies {
        let locked = ["dependencies", "optionalDependencies"]
            .into_iter()
            .find_map(|section| importer.get(section)?.get(&dependency.name));
        let Some(locked) = locked else { continue };
        let (specifier, reference) = if let Some(reference) = locked.as_str() {
            (
                importer
                    .get("specifiers")
                    .and_then(|v| v.get(&dependency.name))
                    .and_then(JsonValue::as_str),
                Some(reference),
            )
        } else {
            (
                locked.get("specifier").and_then(JsonValue::as_str),
                locked.get("version").and_then(JsonValue::as_str),
            )
        };
        if specifier.is_some_and(|specifier| specifier != dependency.requirement) {
            continue;
        }
        let Some(reference) = reference else {
            continue;
        };
        if let Some((archive, commit)) = github_archive(reference) {
            dependency.resolved_version = Some(commit);
            dependency.source_url = Some(archive);
            dependency.lockfile = Some(path.to_owned());
            continue;
        }
        if reference.starts_with("link:")
            || reference.starts_with("workspace:")
            || reference.starts_with("file:")
            || reference.starts_with("npm:")
        {
            continue;
        }
        let resolved = reference.split('(').next().unwrap_or(reference);
        let candidates = package_keys(&dependency.name, resolved, &version);
        let Some(package) = packages.and_then(|packages| {
            candidates
                .iter()
                .find_map(|candidate| packages.get(candidate))
        }) else {
            continue;
        };
        let resolution = package.get("resolution").unwrap_or(package);
        let Some(integrity) = resolution.get("integrity").and_then(JsonValue::as_str) else {
            continue;
        };
        dependency.resolved_version = Some(resolved.to_owned());
        dependency.integrity = Some(integrity.to_owned());
        dependency.source_url = resolution
            .get("tarball")
            .and_then(JsonValue::as_str)
            .filter(|url| url.starts_with("http://") || url.starts_with("https://"))
            .map(str::to_owned)
            .or_else(|| Some(tarball_url(&dependency.name, resolved)));
        dependency.lockfile = Some(path.to_owned());
    }
    Ok(())
}

fn yaml_json(path: &Path) -> Result<JsonValue> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(&read(path)?).map_err(|error| manifest_error(path, error))?;
    serde_json::to_value(value).map_err(|error| manifest_error(path, error))
}

fn package_keys(name: &str, version: &str, lock_version: &str) -> Vec<String> {
    if lock_version.starts_with('5') {
        vec![format!("/{name}/{version}")]
    } else if lock_version.starts_with('6') {
        vec![format!("/{name}@{version}")]
    } else {
        vec![format!("{name}@{version}"), format!("/{name}@{version}")]
    }
}

fn tarball_url(name: &str, version: &str) -> String {
    let base = name.rsplit('/').next().unwrap_or(name);
    format!("https://registry.npmjs.org/{name}/-/{base}-{version}.tgz")
}
