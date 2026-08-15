use std::{path::Path, str::FromStr};

use pep440_rs::{Version, VersionSpecifiers};
use toml::Value as TomlValue;

use super::shared::declared_dependency;
use crate::{
    error::Result,
    manifests::shared::{BoundedDependencyCollector, manifest_error},
    model::Dependency,
};

pub(super) fn parse_poetry_dependencies(
    path: &Path,
    manifest: &TomlValue,
    dependencies: &mut BoundedDependencyCollector,
) -> Result<()> {
    let Some(poetry) = manifest.get("tool").and_then(|value| value.get("poetry")) else {
        return Ok(());
    };
    let poetry = poetry
        .as_table()
        .ok_or_else(|| manifest_error(path, "Poetry configuration must be a table"))?;

    for section in ["dependencies", "dev-dependencies"] {
        if let Some(entries) = poetry.get(section) {
            collect_poetry_dependencies(
                path,
                section,
                entries,
                dependencies,
                section == "dependencies",
            )?;
        }
    }

    let Some(groups) = poetry.get("group") else {
        return Ok(());
    };
    let groups = groups
        .as_table()
        .ok_or_else(|| manifest_error(path, "Poetry groups must be a table"))?;
    for (group_name, group) in groups {
        let group = group.as_table().ok_or_else(|| {
            manifest_error(path, format!("Poetry group {group_name} must be a table"))
        })?;
        if let Some(entries) = group.get("dependencies") {
            collect_poetry_dependencies(
                path,
                &format!("Poetry group {group_name} dependencies"),
                entries,
                dependencies,
                false,
            )?;
        }
    }
    Ok(())
}

fn collect_poetry_dependencies(
    path: &Path,
    section: &str,
    entries: &TomlValue,
    dependencies: &mut BoundedDependencyCollector,
    skip_python: bool,
) -> Result<()> {
    let entries = entries
        .as_table()
        .ok_or_else(|| manifest_error(path, format!("{section} must be a table")))?;
    for (name, spec) in entries {
        if !spec.is_str() && !spec.is_table() {
            return Err(manifest_error(
                path,
                format!("Poetry dependency entry {name} must be a string or table"),
            ));
        }
        if skip_python && name == "python" {
            continue;
        }

        dependencies.push(poetry_dependency(path, name, spec)?)?;
    }
    Ok(())
}

pub(super) fn poetry_dependency(path: &Path, name: &str, spec: &TomlValue) -> Result<Dependency> {
    let requirement = poetry_requirement(path, name, spec)?;
    let mut dependency = declared_dependency(name, &requirement, &requirement);
    if let Some(table) = spec.as_table() {
        if let Some(url) = table.get("url").and_then(TomlValue::as_str) {
            dependency.source_url = Some(url.to_owned());
        } else if let Some(git) = table.get("git").and_then(TomlValue::as_str)
            && dependency.source_url.is_none()
        {
            dependency.source_url = Some(git.to_owned());
        }
    }
    Ok(dependency)
}

pub(super) fn poetry_requirement(path: &Path, name: &str, spec: &TomlValue) -> Result<String> {
    if let Some(version) = spec.as_str() {
        return requirement_with_poetry_constraint(path, name, version);
    }

    let table = spec
        .as_table()
        .expect("Poetry dependency entry type was validated before building its requirement");
    let url = poetry_direct_source(path, name, table, "url")?;
    let dependency_path = poetry_direct_source(path, name, table, "path")?;
    let git = poetry_direct_source(path, name, table, "git")?;
    if let Some(url) = url {
        Ok(format!("{name} @ {url}"))
    } else if let Some(dependency_path) = dependency_path {
        Ok(format!("file:{dependency_path}"))
    } else if let Some(git) = git {
        let revision = table
            .get("rev")
            .and_then(TomlValue::as_str)
            .ok_or_else(|| {
                manifest_error(
                    path,
                    format!("Poetry Git dependency {name} must pin an immutable rev"),
                )
            })?;
        if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(manifest_error(
                path,
                format!("Poetry Git dependency {name} rev must be a 40-character commit SHA"),
            ));
        }
        Ok(format!("git+{git}#{revision}"))
    } else {
        requirement_with_poetry_constraint(
            path,
            name,
            table
                .get("version")
                .and_then(TomlValue::as_str)
                .unwrap_or("*"),
        )
    }
}

fn poetry_direct_source<'a>(
    path: &Path,
    name: &str,
    table: &'a toml::map::Map<String, TomlValue>,
    field: &str,
) -> Result<Option<&'a str>> {
    table
        .get(field)
        .map(|value| {
            value.as_str().ok_or_else(|| {
                manifest_error(
                    path,
                    format!("Poetry dependency {name} {field} must be a string"),
                )
            })
        })
        .transpose()
}

fn requirement_with_poetry_constraint(path: &Path, name: &str, constraint: &str) -> Result<String> {
    let constraint = constraint.trim();
    if constraint.is_empty() || constraint == "*" {
        return Ok(name.to_owned());
    }
    if constraint.contains("||") {
        return Err(manifest_error(
            path,
            format!("Poetry dependency {name} uses an unsupported version union"),
        ));
    }

    let translated = constraint
        .split(',')
        .flat_map(|part| part.split_whitespace())
        .filter(|part| !part.is_empty())
        .map(translate_poetry_constraint)
        .collect::<Vec<_>>()
        .join(",");
    VersionSpecifiers::from_str(&translated).map_err(|error| {
        manifest_error(
            path,
            format!("Poetry dependency {name} has an unsupported or invalid constraint: {error}"),
        )
    })?;
    Ok(format!("{name}{translated}"))
}

fn translate_poetry_constraint(constraint: &str) -> String {
    if let Some(version) = constraint.strip_prefix('^') {
        return compatible_range(version, true).unwrap_or_else(|| constraint.to_owned());
    }
    if let Some(version) = constraint.strip_prefix('~')
        && !constraint.starts_with("~=")
    {
        return compatible_range(version, false).unwrap_or_else(|| constraint.to_owned());
    }
    if constraint.contains('*') && !constraint.starts_with("==") && !constraint.starts_with("!=") {
        return format!("=={constraint}");
    }
    if constraint.starts_with(['<', '>', '=', '!']) {
        constraint.to_owned()
    } else {
        format!("=={constraint}")
    }
}

fn compatible_range(version: &str, caret: bool) -> Option<String> {
    let version = Version::from_str(version).ok()?;
    let release = version.release();
    let upper_index = if caret {
        release
            .iter()
            .position(|component| *component != 0)
            .unwrap_or(release.len() - 1)
    } else if release.len() > 1 {
        1
    } else {
        0
    };
    let mut upper = release[..=upper_index].to_vec();
    upper[upper_index] = upper[upper_index].checked_add(1)?;
    let upper = Version::new(upper).with_epoch(version.epoch());
    Some(format!(">={version},<{upper}"))
}
