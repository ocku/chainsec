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
    Pdm(PathBuf),
}

impl PythonLockContext {
    fn find(root: &Path) -> Option<Self> {
        [
            Self::Poetry(root.join("poetry.lock")),
            Self::Pipfile(root.join("Pipfile.lock")),
            Self::Uv(root.join("uv.lock")),
            Self::Pdm(root.join("pdm.lock")),
        ]
        .into_iter()
        .find(|context| context.path().is_file())
    }

    fn path(&self) -> &Path {
        match self {
            Self::Poetry(path) | Self::Pipfile(path) | Self::Uv(path) | Self::Pdm(path) => path,
        }
    }

    fn enrich(&self, dependencies: &mut [Dependency]) -> Result<()> {
        match self {
            Self::Poetry(path) => enrich_poetry(path, dependencies),
            Self::Pipfile(path) => enrich_pipfile(path, dependencies),
            Self::Uv(path) => enrich_uv(path, dependencies),
            Self::Pdm(path) => enrich_pdm(path, dependencies),
        }
    }
}

pub(super) fn parse(path: &Path) -> Result<Vec<Dependency>> {
    let text = read(path)?;
    let value: TomlValue = toml::from_str(&text).map_err(|error| manifest_error(path, error))?;
    let mut dependencies = Vec::new();

    parse_project_dependencies(path, &value, &mut dependencies)?;
    parse_poetry_dependencies(path, &value, &mut dependencies)?;
    Ok(dependencies)
}

fn parse_project_dependencies(
    path: &Path,
    manifest: &TomlValue,
    dependencies: &mut Vec<Dependency>,
) -> Result<()> {
    let Some(entries) = manifest
        .get("project")
        .and_then(|value| value.get("dependencies"))
    else {
        return Ok(());
    };
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
        dependencies.push(dependency_from_requirement(requirement));
    }
    Ok(())
}

fn parse_poetry_dependencies(
    path: &Path,
    manifest: &TomlValue,
    dependencies: &mut Vec<Dependency>,
) -> Result<()> {
    let Some(poetry) = manifest
        .get("tool")
        .and_then(|value| value.get("poetry"))
        .and_then(|value| value.get("dependencies"))
    else {
        return Ok(());
    };
    let poetry = poetry
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

        let requirement = poetry_requirement(name, spec);
        dependencies.push(declared_dependency(name, &requirement, &requirement));
    }
    Ok(())
}

fn poetry_requirement(name: &str, spec: &TomlValue) -> String {
    if let Some(version) = spec.as_str() {
        return format!("{name}{version}");
    }

    let table = spec
        .as_table()
        .expect("Poetry dependency entry type was validated before building its requirement");
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
}

fn dependency_from_requirement(requirement: &str) -> Dependency {
    let before_marker = requirement.split(';').next().unwrap_or(requirement).trim();
    let name = before_marker
        .split(['<', '>', '=', '!', '~', '[', ' ', '@'])
        .next()
        .unwrap_or(before_marker)
        .trim();
    let mut dependency = declared_dependency(name, requirement, before_marker);
    if dependency.source_url.is_none()
        && let Some((_, url)) = before_marker.split_once('@')
    {
        dependency.source_url = Some(url.trim().to_owned());
    }
    dependency
}

fn declared_dependency(name: &str, requirement: &str, source_requirement: &str) -> Dependency {
    let mut dependency = Dependency::declared(Ecosystem::Python, name, requirement);
    if let Some((archive, commit)) = github_archive(source_requirement) {
        dependency.resolved_version = Some(commit);
        dependency.source_url = Some(archive);
    }
    dependency
}

pub(super) fn enrich(
    root: &Path,
    dependencies: &mut [Dependency],
    lockfiles: &mut Vec<PathBuf>,
    inherited_context: Option<&PythonLockContext>,
) -> Result<Option<PythonLockContext>> {
    let context = PythonLockContext::find(root).or_else(|| inherited_context.cloned());
    let Some(context) = context else {
        return Ok(None);
    };

    context.enrich(dependencies)?;
    let path = context.path();
    if !lockfiles.iter().any(|lockfile| lockfile == path) {
        lockfiles.push(path.to_owned());
    }
    Ok(Some(context))
}

fn enrich_poetry(path: &Path, dependencies: &mut [Dependency]) -> Result<()> {
    enrich_toml_packages(path, dependencies, |dependency, package| {
        if dependency.is_pinned_github() {
            return;
        }
        dependency.resolved_version = package_string(package, "version");
        dependency.integrity = package
            .get("files")
            .and_then(TomlValue::as_array)
            .and_then(|files| files.first())
            .and_then(|file| package_string(file, "hash"));
    })
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
    enrich_toml_packages(path, dependencies, |dependency, package| {
        dependency.resolved_version = package_string(package, "version");
        let artifact = package.get("sdist").or_else(|| {
            package
                .get("wheels")
                .and_then(TomlValue::as_array)
                .and_then(|wheels| wheels.first())
        });
        dependency.source_url = artifact.and_then(|artifact| package_string(artifact, "url"));
        dependency.integrity = artifact.and_then(|artifact| package_string(artifact, "hash"));
    })
}

fn enrich_pdm(path: &Path, dependencies: &mut [Dependency]) -> Result<()> {
    enrich_toml_packages(path, dependencies, |dependency, package| {
        dependency.resolved_version = package_string(package, "version");
        dependency.integrity = package
            .get("files")
            .and_then(TomlValue::as_array)
            .and_then(|files| files.first())
            .and_then(|file| package_string(file, "hash"));
    })
}

fn enrich_toml_packages(
    path: &Path,
    dependencies: &mut [Dependency],
    mut enrich: impl FnMut(&mut Dependency, &TomlValue),
) -> Result<()> {
    let value: TomlValue =
        toml::from_str(&read(path)?).map_err(|error| manifest_error(path, error))?;
    let packages = value
        .get("package")
        .and_then(TomlValue::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();

    for dependency in dependencies {
        if let Some(package) = find_package(packages, &dependency.name) {
            enrich(dependency, package);
            dependency.lockfile = Some(path.to_owned());
        }
    }
    Ok(())
}

fn package_string(package: &TomlValue, key: &str) -> Option<String> {
    package
        .get(key)
        .and_then(TomlValue::as_str)
        .map(str::to_owned)
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
