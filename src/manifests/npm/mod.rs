use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use serde_json::Value as JsonValue;

use super::{
    NpmLockContext,
    shared::{github_archive, manifest_error, read},
};
use crate::{
    error::Result,
    model::{Dependency, Ecosystem},
};

mod package_lock;
mod pnpm;
mod yarn;

pub(super) fn install_scripts(path: &Path) -> Result<Option<Vec<String>>> {
    let value: JsonValue =
        serde_json::from_str(&read(path)?).map_err(|error| manifest_error(path, error))?;
    let Some(scripts) = value.get("scripts").and_then(JsonValue::as_object) else {
        return Ok(None);
    };
    let lifecycle = ["preinstall", "install", "postinstall"];
    let found = lifecycle
        .into_iter()
        .filter(|name| scripts.contains_key(*name))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    Ok((!found.is_empty()).then_some(found))
}

pub(super) fn parse(path: &Path) -> Result<Vec<Dependency>> {
    let value: JsonValue =
        serde_json::from_str(&read(path)?).map_err(|error| manifest_error(path, error))?;
    let mut by_name = HashMap::new();
    for section in ["dependencies", "optionalDependencies", "peerDependencies"] {
        if let Some(entries) = value.get(section).and_then(JsonValue::as_object) {
            for (name, value) in entries {
                let requirement = value.as_str().ok_or_else(|| {
                    manifest_error(path, format!("{section}.{name} must be a string"))
                })?;
                let mut dependency = Dependency::declared(Ecosystem::Npm, name, requirement);
                if let Some((archive, commit)) = github_archive(requirement) {
                    dependency.resolved_version = Some(commit);
                    dependency.source_url = Some(archive);
                }
                by_name.insert(name.clone(), dependency);
            }
        }
    }
    Ok(by_name.into_values().collect())
}

pub(super) fn enrich(
    root: &Path,
    dependencies: &mut [Dependency],
    lockfiles: &mut Vec<PathBuf>,
) -> Result<HashMap<String, NpmLockContext>> {
    let Some(path) = ["npm-shrinkwrap.json", "package-lock.json"]
        .into_iter()
        .map(|name| root.join(name))
        .find(|path| path.is_file())
    else {
        enrich_alternative_lock(root, dependencies, lockfiles)?;
        return Ok(HashMap::new());
    };
    let context = NpmLockContext {
        lockfile: path.clone(),
        package_path: String::new(),
    };
    let contexts = enrich_from_context(&context, dependencies)?;
    lockfiles.push(path);
    Ok(contexts)
}

pub(super) fn enrich_from_context(
    context: &NpmLockContext,
    dependencies: &mut [Dependency],
) -> Result<HashMap<String, NpmLockContext>> {
    package_lock::enrich(context, dependencies)
}

fn enrich_alternative_lock(
    root: &Path,
    dependencies: &mut [Dependency],
    lockfiles: &mut Vec<PathBuf>,
) -> Result<()> {
    let yarn_path = root.join("yarn.lock");
    let pnpm_path = root.join("pnpm-lock.yaml");
    if yarn_path.is_file() && pnpm_path.is_file() {
        return Err(manifest_error(
            &yarn_path,
            "both yarn.lock and pnpm-lock.yaml are present; lockfile selection is ambiguous",
        ));
    }
    if pnpm_path.is_file() {
        pnpm::enrich(&pnpm_path, dependencies)?;
        lockfiles.push(pnpm_path);
    } else if yarn_path.is_file() {
        yarn::enrich(&yarn_path, dependencies)?;
        lockfiles.push(yarn_path);
    }
    Ok(())
}
