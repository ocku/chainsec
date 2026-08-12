use std::path::Path;

use ::toml::Value as TomlValue;

use super::super::matching::{find_package, index_toml_packages};
use crate::{
    error::Result,
    manifests::shared::{manifest_error, read},
    model::Dependency,
};

pub(super) fn enrich_toml_packages(
    path: &Path,
    dependencies: &mut Vec<Dependency>,
    mut enrich: impl FnMut(&Dependency, &TomlValue) -> Result<Vec<Dependency>>,
) -> Result<()> {
    let value: TomlValue =
        ::toml::from_str(&read(path)?).map_err(|error| manifest_error(path, error))?;
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
            let mut artifacts = enrich(&dependency, package)?;
            for artifact in &mut artifacts {
                artifact.lockfile = Some(path.to_owned());
            }
            enriched.extend(artifacts);
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
