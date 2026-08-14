use std::path::Path;

use ::toml::Value as TomlValue;

use super::super::matching::{find_package, index_toml_packages};
use crate::{
    error::Result,
    manifests::shared::{manifest_error, read},
    model::Dependency,
};

#[derive(Clone, Copy)]
pub(super) enum LockSchema {
    Poetry,
    Uv,
    Pdm,
}

impl LockSchema {
    fn validate(self, path: &Path, value: &TomlValue) -> Result<()> {
        let (actual, expected, format) = match self {
            Self::Poetry => (
                value
                    .get("metadata")
                    .and_then(|metadata| metadata.get("lock-version"))
                    .and_then(TomlValue::as_str),
                "2.0",
                "Poetry",
            ),
            Self::Pdm => (
                value
                    .get("metadata")
                    .and_then(|metadata| metadata.get("lock_version"))
                    .and_then(TomlValue::as_str),
                "4.5.0",
                "PDM",
            ),
            Self::Uv => {
                let version = value.get("version").and_then(TomlValue::as_integer);
                if version == Some(1) {
                    return Ok(());
                }
                return Err(manifest_error(
                    path,
                    "uv lockfile must have supported integer version 1",
                ));
            }
        };
        if actual == Some(expected) {
            Ok(())
        } else {
            Err(manifest_error(
                path,
                format!("{format} lockfile must have supported schema version {expected}"),
            ))
        }
    }
}

pub(super) fn enrich_toml_packages(
    path: &Path,
    dependencies: &mut Vec<Dependency>,
    max_packages: usize,
    schema: LockSchema,
    mut enrich: impl FnMut(&Dependency, &TomlValue, usize) -> Result<Vec<Dependency>>,
) -> Result<()> {
    let value: TomlValue =
        ::toml::from_str(&read(path)?).map_err(|error| manifest_error(path, error))?;
    schema.validate(path, &value)?;
    let packages = value
        .get("package")
        .ok_or_else(|| manifest_error(path, "Python lockfile package array is missing"))?
        .as_array()
        .ok_or_else(|| manifest_error(path, "Python lockfile package must be an array"))?;
    for (index, package) in packages.iter().enumerate() {
        let table = package.as_table().ok_or_else(|| {
            manifest_error(
                path,
                format!("Python lockfile package entry {index} must be a table"),
            )
        })?;
        if !table.get("name").is_some_and(TomlValue::is_str) {
            return Err(manifest_error(
                path,
                format!("Python lockfile package entry {index} has no string name"),
            ));
        }
        if !table.get("version").is_some_and(TomlValue::is_str) {
            return Err(manifest_error(
                path,
                format!("Python lockfile package entry {index} has no string version"),
            ));
        }
    }

    let index = index_toml_packages(packages);
    let declared = std::mem::take(dependencies);
    let mut enriched = Vec::with_capacity(declared.len());
    for dependency in declared {
        if let Some(package) = find_package(path, &index, &dependency)? {
            let remaining = max_packages.saturating_sub(enriched.len());
            let mut artifacts = enrich(&dependency, package, remaining)?;
            for artifact in &mut artifacts {
                artifact.lockfile = Some(path.to_owned());
            }
            crate::manifests::shared::extend_dependencies_bounded(
                &mut enriched,
                artifacts,
                max_packages,
            )?;
        } else {
            enriched.push(dependency);
        }
    }
    *dependencies = enriched;
    Ok(())
}

pub(in crate::manifests::python) fn package_string(
    package: &TomlValue,
    key: &str,
) -> Option<String> {
    package
        .get(key)
        .and_then(TomlValue::as_str)
        .map(str::to_owned)
}
