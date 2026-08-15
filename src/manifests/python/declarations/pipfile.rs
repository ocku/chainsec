use std::path::Path;

use toml::Value as TomlValue;

use super::shared::{dependency_from_requirement, parse_toml};
use crate::{
    error::Result,
    manifests::shared::{BoundedDependencyCollector, manifest_error},
    model::Dependency,
};

pub(in crate::manifests) fn parse_pipfile_with_limit(
    path: &Path,
    max_packages: usize,
) -> Result<Vec<Dependency>> {
    let value = parse_toml(path)?;
    let mut dependencies = BoundedDependencyCollector::new(max_packages);

    for section in ["packages", "dev-packages"] {
        let Some(entries) = value.get(section) else {
            continue;
        };
        let entries = entries
            .as_table()
            .ok_or_else(|| manifest_error(path, format!("Pipfile {section} must be a table")))?;
        for (name, spec) in entries {
            dependencies.push(pipfile_dependency(path, name, spec)?)?;
        }
    }
    Ok(dependencies.into_dependencies())
}

fn pipfile_dependency(path: &Path, name: &str, spec: &TomlValue) -> Result<Dependency> {
    let (version, extras, markers, source_url) = match spec {
        TomlValue::String(version) => (version.as_str(), Vec::new(), None, None),
        TomlValue::Table(table) => {
            let mut unsupported = table
                .keys()
                .filter(|key| {
                    !matches!(
                        key.as_str(),
                        "version" | "extras" | "markers" | "file" | "path"
                    )
                })
                .cloned()
                .collect::<Vec<_>>();
            if !unsupported.is_empty() {
                unsupported.sort_unstable();
                return Err(manifest_error(
                    path,
                    format!(
                        "Pipfile dependency {name} uses unsupported table keys: {}; supported keys are version, extras, markers, file, and path",
                        unsupported.join(", ")
                    ),
                ));
            }
            if table.contains_key("file") && table.contains_key("path") {
                return Err(manifest_error(
                    path,
                    format!("Pipfile dependency {name} cannot specify both file and path"),
                ));
            }

            let version = match table.get("version") {
                Some(value) => value.as_str().ok_or_else(|| {
                    manifest_error(
                        path,
                        format!("Pipfile dependency {name} version must be a string"),
                    )
                })?,
                None => "*",
            };
            let extras = match table.get("extras") {
                Some(value) => value
                    .as_array()
                    .ok_or_else(|| {
                        manifest_error(
                            path,
                            format!("Pipfile dependency {name} extras must be an array"),
                        )
                    })?
                    .iter()
                    .map(TomlValue::as_str)
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(|| {
                        manifest_error(
                            path,
                            format!("Pipfile dependency {name} extras must be strings"),
                        )
                    })?,
                None => Vec::new(),
            };
            let markers = match table.get("markers") {
                Some(value) => Some(value.as_str().ok_or_else(|| {
                    manifest_error(
                        path,
                        format!("Pipfile dependency {name} markers must be a string"),
                    )
                })?),
                None => None,
            };
            let source_url = if let Some(value) = table.get("file") {
                Some(value.as_str().ok_or_else(|| {
                    manifest_error(
                        path,
                        format!("Pipfile dependency {name} file must be a string"),
                    )
                })?)
            } else if let Some(value) = table.get("path") {
                Some(value.as_str().ok_or_else(|| {
                    manifest_error(
                        path,
                        format!("Pipfile dependency {name} path must be a string"),
                    )
                })?)
            } else {
                None
            };
            (version, extras, markers, source_url)
        }
        _ => {
            return Err(manifest_error(
                path,
                format!("Pipfile dependency {name} must be a string or table"),
            ));
        }
    };

    let extras = if extras.is_empty() {
        String::new()
    } else {
        format!("[{}]", extras.join(","))
    };
    let version = if version == "*" { "" } else { version };
    let mut requirement = format!("{name}{extras}{version}");
    if let Some(markers) = markers {
        requirement.push_str("; ");
        requirement.push_str(markers);
    }
    if let Some(source_url) = source_url {
        requirement = format!("{name}{extras} @ {source_url}");
    }
    Ok(dependency_from_requirement(&requirement))
}
