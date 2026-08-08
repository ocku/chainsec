use std::path::Path;

use serde_json::{Map, Value as JsonValue};

use crate::manifests::shared::{github_archive, manifest_error, read};
use crate::{error::Result, model::Dependency};

pub(super) fn enrich(path: &Path, dependencies: &mut [Dependency]) -> Result<()> {
    let lockfile = yaml_json(path)?;
    let version = lockfile_version(path, &lockfile)?;
    let importer = importer(&lockfile);
    let packages = lockfile.get("packages").and_then(JsonValue::as_object);

    for dependency in dependencies {
        let Some((specifier, reference)) = locked_reference(importer, dependency) else {
            continue;
        };
        if specifier.is_some_and(|specifier| specifier != dependency.requirement) {
            continue;
        }

        enrich_dependency(dependency, reference, packages, &version, path);
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

fn importer(lockfile: &JsonValue) -> &JsonValue {
    lockfile
        .get("importers")
        .and_then(|importers| importers.get("."))
        .unwrap_or(lockfile)
}

fn locked_reference<'a>(
    importer: &'a JsonValue,
    dependency: &Dependency,
) -> Option<(Option<&'a str>, &'a str)> {
    let locked = ["dependencies", "optionalDependencies"]
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
) {
    if let Some((archive, commit)) = github_archive(reference) {
        dependency.resolved_version = Some(commit);
        dependency.source_url = Some(archive);
        dependency.lockfile = Some(path.to_owned());
        return;
    }
    if is_local_reference(reference) {
        return;
    }

    let version = reference.split('(').next().unwrap_or(reference);
    let Some(package) = find_package(packages, &dependency.name, version, lockfile_version) else {
        return;
    };
    let resolution = package.get("resolution").unwrap_or(package);
    let Some(integrity) = resolution.get("integrity").and_then(JsonValue::as_str) else {
        return;
    };

    dependency.resolved_version = Some(version.to_owned());
    dependency.integrity = Some(integrity.to_owned());
    dependency.source_url = registry_tarball(resolution, &dependency.name, version);
    dependency.lockfile = Some(path.to_owned());
}

fn is_local_reference(reference: &str) -> bool {
    ["link:", "workspace:", "file:", "npm:"]
        .into_iter()
        .any(|prefix| reference.starts_with(prefix))
}

fn find_package<'a>(
    packages: Option<&'a Map<String, JsonValue>>,
    name: &str,
    version: &str,
    lockfile_version: &str,
) -> Option<&'a JsonValue> {
    let packages = packages?;
    package_keys(name, version, lockfile_version)
        .into_iter()
        .find_map(|key| packages.get(&key))
}

fn registry_tarball(resolution: &JsonValue, name: &str, version: &str) -> Option<String> {
    resolution
        .get("tarball")
        .and_then(JsonValue::as_str)
        .filter(|url| url.starts_with("http://") || url.starts_with("https://"))
        .map(str::to_owned)
        .or_else(|| Some(tarball_url(name, version)))
}

fn yaml_json(path: &Path) -> Result<JsonValue> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(&read(path)?).map_err(|error| manifest_error(path, error))?;
    serde_json::to_value(value).map_err(|error| manifest_error(path, error))
}

fn package_keys(name: &str, version: &str, lockfile_version: &str) -> Vec<String> {
    if lockfile_version.starts_with('5') {
        vec![format!("/{name}/{version}")]
    } else if lockfile_version.starts_with('6') {
        vec![format!("/{name}@{version}")]
    } else {
        vec![format!("{name}@{version}"), format!("/{name}@{version}")]
    }
}

fn tarball_url(name: &str, version: &str) -> String {
    let base = name.rsplit('/').next().unwrap_or(name);
    format!("https://registry.npmjs.org/{name}/-/{base}-{version}.tgz")
}
