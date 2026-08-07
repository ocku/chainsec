use std::path::{Path, PathBuf};

use serde_json::Value as JsonValue;
use toml::Value as TomlValue;

use super::shared::{github_archive, manifest_error, read};
use crate::{
    error::Result,
    model::{Dependency, Ecosystem},
};

#[derive(Debug, Clone)]
pub(crate) enum PythonLockContext {
    Poetry(PathBuf),
    Pipfile(PathBuf),
    Uv(PathBuf),
}

pub(super) fn parse(path: &Path) -> Result<Vec<Dependency>> {
    let text = read(path)?;
    let value: TomlValue = toml::from_str(&text).map_err(|error| manifest_error(path, error))?;
    let mut result = Vec::new();

    if let Some(entries) = value.get("project").and_then(|v| v.get("dependencies")) {
        let entries = entries
            .as_array()
            .ok_or_else(|| manifest_error(path, "Python project.dependencies must be an array"))?;
        for (index, requirement) in entries.iter().enumerate() {
            let requirement = requirement.as_str().ok_or_else(|| {
                manifest_error(
                    path,
                    format!("Python project.dependencies entry {index} must be a string"),
                )
            })?;
            result.push(dependency(requirement));
        }
    }

    if let Some(poetry_value) = value
        .get("tool")
        .and_then(|v| v.get("poetry"))
        .and_then(|v| v.get("dependencies"))
    {
        let poetry = poetry_value
            .as_table()
            .ok_or_else(|| manifest_error(path, "Poetry dependencies must be a table"))?;
        for (name, spec) in poetry {
            if !spec.is_str() && !spec.is_table() {
                return Err(manifest_error(
                    path,
                    format!("Poetry dependency entry {name} must be a string or table"),
                ));
            }
            if name == "python" {
                continue;
            }
            let requirement = if let Some(version) = spec.as_str() {
                format!("{name}{version}")
            } else if let Some(table) = spec.as_table() {
                if let Some(url) = table.get("url").and_then(TomlValue::as_str) {
                    format!("{name} @ {url}")
                } else if let Some(path) = table.get("path").and_then(TomlValue::as_str) {
                    format!("file:{path}")
                } else if let (Some(git), Some(revision)) = (
                    table.get("git").and_then(TomlValue::as_str),
                    table.get("rev").and_then(TomlValue::as_str),
                ) {
                    format!("git+{git}#{revision}")
                } else {
                    format!(
                        "{name}{}",
                        table
                            .get("version")
                            .and_then(TomlValue::as_str)
                            .unwrap_or("*")
                    )
                }
            } else {
                unreachable!("Poetry dependency entry type was validated above")
            };
            let mut dependency = Dependency::declared(Ecosystem::Python, name, &requirement);
            if let Some((archive, commit)) = github_archive(&requirement) {
                dependency.resolved_version = Some(commit);
                dependency.source_url = Some(archive);
            }
            result.push(dependency);
        }
    }
    Ok(result)
}

fn dependency(requirement: &str) -> Dependency {
    let before_marker = requirement.split(';').next().unwrap_or(requirement).trim();
    let name = before_marker
        .split(['<', '>', '=', '!', '~', '[', ' ', '@'])
        .next()
        .unwrap_or(before_marker)
        .trim();
    let mut dependency = Dependency::declared(Ecosystem::Python, name, requirement);
    if let Some((archive, commit)) = github_archive(before_marker) {
        dependency.resolved_version = Some(commit);
        dependency.source_url = Some(archive);
    } else if let Some((_, url)) = before_marker.split_once('@') {
        dependency.source_url = Some(url.trim().to_owned());
    }
    dependency
}

pub(super) fn enrich(
    root: &Path,
    dependencies: &mut [Dependency],
    lockfiles: &mut Vec<PathBuf>,
    inherited_context: Option<&PythonLockContext>,
) -> Result<Option<PythonLockContext>> {
    let context = [
        PythonLockContext::Poetry(root.join("poetry.lock")),
        PythonLockContext::Pipfile(root.join("Pipfile.lock")),
        PythonLockContext::Uv(root.join("uv.lock")),
    ]
    .into_iter()
    .find(|context| match context {
        PythonLockContext::Poetry(path)
        | PythonLockContext::Pipfile(path)
        | PythonLockContext::Uv(path) => path.is_file(),
    })
    .or_else(|| inherited_context.cloned());

    if let Some(context) = context {
        let path = match &context {
            PythonLockContext::Poetry(path)
            | PythonLockContext::Pipfile(path)
            | PythonLockContext::Uv(path) => path,
        };
        match &context {
            PythonLockContext::Poetry(path) => enrich_poetry(path, dependencies)?,
            PythonLockContext::Pipfile(path) => enrich_pipfile(path, dependencies)?,
            PythonLockContext::Uv(path) => enrich_uv(path, dependencies)?,
        }
        if !lockfiles.contains(path) {
            lockfiles.push(path.clone());
        }
        return Ok(Some(context));
    }

    Ok(None)
}

fn enrich_poetry(path: &Path, dependencies: &mut [Dependency]) -> Result<()> {
    let value: TomlValue =
        toml::from_str(&read(path)?).map_err(|error| manifest_error(path, error))?;
    let packages = value
        .get("package")
        .and_then(TomlValue::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    for dependency in dependencies {
        if let Some(package) = find_package(packages, &dependency.name) {
            if dependency.is_pinned_github() {
                dependency.lockfile = Some(path.to_owned());
                continue;
            }
            dependency.resolved_version = package
                .get("version")
                .and_then(TomlValue::as_str)
                .map(str::to_owned);
            if let Some(file) = package
                .get("files")
                .and_then(TomlValue::as_array)
                .and_then(|files| files.first())
            {
                dependency.integrity = file
                    .get("hash")
                    .and_then(TomlValue::as_str)
                    .map(str::to_owned);
            }
            dependency.lockfile = Some(path.to_owned());
        }
    }
    Ok(())
}

fn enrich_pipfile(path: &Path, dependencies: &mut [Dependency]) -> Result<()> {
    let value: JsonValue =
        serde_json::from_str(&read(path)?).map_err(|error| manifest_error(path, error))?;
    for dependency in dependencies {
        let entry = ["default", "develop"]
            .into_iter()
            .find_map(|section| value.get(section)?.get(&dependency.name));
        if let Some(entry) = entry {
            dependency.resolved_version = entry
                .get("version")
                .and_then(JsonValue::as_str)
                .map(|value| value.trim_start_matches("==").to_owned());
            dependency.integrity = entry
                .get("hashes")
                .and_then(JsonValue::as_array)
                .and_then(|hashes| hashes.first())
                .and_then(JsonValue::as_str)
                .map(str::to_owned);
            dependency.lockfile = Some(path.to_owned());
        }
    }
    Ok(())
}

fn enrich_uv(path: &Path, dependencies: &mut [Dependency]) -> Result<()> {
    let value: TomlValue =
        toml::from_str(&read(path)?).map_err(|error| manifest_error(path, error))?;
    let packages = value
        .get("package")
        .and_then(TomlValue::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    for dependency in dependencies {
        if let Some(package) = find_package(packages, &dependency.name) {
            dependency.resolved_version = package
                .get("version")
                .and_then(TomlValue::as_str)
                .map(str::to_owned);
            let artifact = package.get("sdist").or_else(|| {
                package
                    .get("wheels")
                    .and_then(TomlValue::as_array)
                    .and_then(|v| v.first())
            });
            dependency.source_url = artifact
                .and_then(|v| v.get("url"))
                .and_then(TomlValue::as_str)
                .map(str::to_owned);
            dependency.integrity = artifact
                .and_then(|v| v.get("hash"))
                .and_then(TomlValue::as_str)
                .map(str::to_owned);
            dependency.lockfile = Some(path.to_owned());
        }
    }
    Ok(())
}

fn find_package<'a>(packages: &'a [TomlValue], name: &str) -> Option<&'a TomlValue> {
    let normalized_name = normalize(name);
    packages.iter().find(|package| {
        package
            .get("name")
            .and_then(TomlValue::as_str)
            .is_some_and(|candidate| normalize(candidate) == normalized_name)
    })
}

fn normalize(name: &str) -> String {
    name.to_ascii_lowercase().replace(['_', '.'], "-")
}
