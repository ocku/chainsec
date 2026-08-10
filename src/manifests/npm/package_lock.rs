use std::collections::HashMap;

use serde_json::Value as JsonValue;

use crate::manifests::{
    NpmLockContext,
    shared::{github_archive, manifest_error, read, strip_url_fragment},
};
use crate::{error::Result, model::Dependency};

pub(super) fn enrich(
    context: &NpmLockContext,
    dependencies: &mut [Dependency],
) -> Result<HashMap<String, NpmLockContext>> {
    let path = &context.lockfile;
    let value: JsonValue =
        serde_json::from_str(&read(path)?).map_err(|error| manifest_error(path, error))?;
    let version = value
        .get("lockfileVersion")
        .and_then(JsonValue::as_u64)
        .unwrap_or(1);
    if !(1..=3).contains(&version) {
        return Err(manifest_error(
            path,
            format!("unsupported npm lockfile version {version}"),
        ));
    }

    let packages = value.get("packages").and_then(JsonValue::as_object);
    let legacy_dependencies = value.get("dependencies").and_then(JsonValue::as_object);
    let mut contexts = HashMap::new();
    for dependency in dependencies {
        let resolved_package = packages.and_then(|packages| {
            resolve_package_path(packages, &context.package_path, &dependency.name).and_then(
                |package_path| {
                    packages
                        .get(&package_path)
                        .map(|value| (package_path, value))
                },
            )
        });
        let (package_path, package) = if let Some((package_path, package)) = resolved_package {
            (Some(package_path), package)
        } else if context.package_path.is_empty() {
            let Some(package) = legacy_dependencies.and_then(|deps| deps.get(&dependency.name))
            else {
                continue;
            };
            (None, package)
        } else {
            continue;
        };

        let resolved = package.get("resolved").and_then(JsonValue::as_str);
        if let Some((archive, commit)) = resolved.and_then(github_archive) {
            dependency.resolved_version = Some(commit);
            dependency.source_url = Some(archive);
        } else {
            dependency.resolved_version = package
                .get("version")
                .and_then(JsonValue::as_str)
                .map(str::to_owned);
            dependency.source_url = resolved.map(strip_url_fragment);
            dependency.integrity = package
                .get("integrity")
                .and_then(JsonValue::as_str)
                .map(str::to_owned);
        }
        dependency.lockfile = Some(path.clone());
        if let Some(package_path) = package_path {
            contexts.insert(
                dependency.id(),
                NpmLockContext {
                    lockfile: path.clone(),
                    package_path,
                },
            );
        }
    }
    Ok(contexts)
}

fn resolve_package_path(
    packages: &serde_json::Map<String, JsonValue>,
    parent_path: &str,
    name: &str,
) -> Option<String> {
    let mut current = parent_path;
    loop {
        let candidate = if current.is_empty() {
            format!("node_modules/{name}")
        } else {
            format!("{current}/node_modules/{name}")
        };
        if packages.contains_key(&candidate) {
            return Some(candidate);
        }
        if current.is_empty() {
            return None;
        }
        current = current
            .rfind("/node_modules/")
            .map_or("", |index| &current[..index]);
    }
}
