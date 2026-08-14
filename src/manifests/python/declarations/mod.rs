use std::{collections::HashSet, path::Path, str::FromStr};

use pep440_rs::{Version, VersionSpecifiers};

use toml::Value as TomlValue;

use super::matching::normalize;
use crate::{
    error::Result,
    manifests::shared::{BoundedDependencyCollector, github_archive, manifest_error, read},
    model::{Dependency, Ecosystem},
};

#[cfg(test)]
pub(in crate::manifests) fn parse(path: &Path) -> Result<Vec<Dependency>> {
    parse_with_limit(path, crate::model::EngineLimits::default().max_packages)
}

pub(in crate::manifests) fn parse_with_limit(
    path: &Path,
    max_packages: usize,
) -> Result<Vec<Dependency>> {
    let value = parse_toml(path)?;
    let mut dependencies = BoundedDependencyCollector::new(max_packages);

    parse_project_dependencies(path, &value, &mut dependencies)?;
    parse_dependency_groups(path, &value, &mut dependencies)?;
    parse_poetry_dependencies(path, &value, &mut dependencies)?;
    Ok(dependencies.into_dependencies())
}

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

fn parse_toml(path: &Path) -> Result<TomlValue> {
    let text = read(path)?;
    toml::from_str(&text).map_err(|error| manifest_error(path, error))
}

fn pipfile_dependency(path: &Path, name: &str, spec: &TomlValue) -> Result<Dependency> {
    let (version, extras, markers, source_url) = match spec {
        TomlValue::String(version) => (version.as_str(), Vec::new(), None, None),
        TomlValue::Table(table) => {
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
            let source_url = table
                .get("file")
                .or_else(|| table.get("path"))
                .and_then(TomlValue::as_str);
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

fn parse_project_dependencies(
    path: &Path,
    manifest: &TomlValue,
    dependencies: &mut BoundedDependencyCollector,
) -> Result<()> {
    let Some(project) = manifest.get("project") else {
        return Ok(());
    };
    let project = project
        .as_table()
        .ok_or_else(|| manifest_error(path, "Python project must be a table"))?;
    if let Some(dynamic) = project.get("dynamic") {
        let dynamic = dynamic
            .as_array()
            .ok_or_else(|| manifest_error(path, "Python project.dynamic must be an array"))?;
        if dynamic.iter().any(|entry| {
            matches!(
                entry.as_str(),
                Some("dependencies" | "optional-dependencies")
            )
        }) {
            return Err(manifest_error(
                path,
                "Python project uses dynamic dependencies; static dependency discovery is incomplete",
            ));
        }
    }
    if let Some(entries) = project.get("dependencies") {
        collect_requirement_array(path, "Python project.dependencies", entries, dependencies)?;
    }
    if let Some(optional) = project.get("optional-dependencies") {
        let optional = optional.as_table().ok_or_else(|| {
            manifest_error(path, "Python project.optional-dependencies must be a table")
        })?;
        for (extra, entries) in optional {
            collect_requirement_array(
                path,
                &format!("Python project.optional-dependencies.{extra}"),
                entries,
                dependencies,
            )?;
        }
    }
    Ok(())
}

fn collect_requirement_array(
    path: &Path,
    section: &str,
    entries: &TomlValue,
    dependencies: &mut BoundedDependencyCollector,
) -> Result<()> {
    let entries = entries
        .as_array()
        .ok_or_else(|| manifest_error(path, format!("{section} must be an array")))?;
    for (index, requirement) in entries.iter().enumerate() {
        let requirement = requirement.as_str().ok_or_else(|| {
            manifest_error(path, format!("{section} entry {index} must be a string"))
        })?;
        dependencies.push(dependency_from_requirement(requirement))?;
    }
    Ok(())
}

struct GroupFrame {
    name: String,
    next_entry: usize,
}

fn parse_dependency_groups(
    path: &Path,
    manifest: &TomlValue,
    dependencies: &mut BoundedDependencyCollector,
) -> Result<()> {
    let Some(groups) = manifest.get("dependency-groups") else {
        return Ok(());
    };
    let groups = groups
        .as_table()
        .ok_or_else(|| manifest_error(path, "Python dependency-groups must be a table"))?;

    let mut visited = HashSet::new();
    let mut active = HashSet::new();

    for root in groups.keys() {
        if visited.contains(root) {
            continue;
        }
        let mut stack = vec![GroupFrame {
            name: root.clone(),
            next_entry: 0,
        }];
        active.insert(root.clone());

        while let Some(frame) = stack.last_mut() {
            let entries = groups
                .get(&frame.name)
                .ok_or_else(|| {
                    manifest_error(
                        path,
                        format!("Python dependency-group {} is missing", frame.name),
                    )
                })?
                .as_array()
                .ok_or_else(|| {
                    manifest_error(
                        path,
                        format!("Python dependency-group {} must be an array", frame.name),
                    )
                })?;

            if frame.next_entry == entries.len() {
                let completed = stack.pop().expect("dependency-group stack is not empty");
                active.remove(&completed.name);
                visited.insert(completed.name);
                continue;
            }

            let index = frame.next_entry;
            frame.next_entry += 1;
            let entry = &entries[index];
            if let Some(requirement) = entry.as_str() {
                dependencies.push(dependency_from_requirement(requirement))?;
                continue;
            }
            let include = entry
                .as_table()
                .and_then(|table| {
                    (table.len() == 1)
                        .then(|| table.get("include-group"))
                        .flatten()
                })
                .and_then(TomlValue::as_str)
                .ok_or_else(|| {
                    manifest_error(
                        path,
                        format!(
                            "Python dependency-group {} entry {index} must be a string or an include-group table",
                            frame.name
                        ),
                    )
                })?;

            if visited.contains(include) {
                continue;
            }
            if active.contains(include) {
                let position = stack
                    .iter()
                    .position(|ancestor| ancestor.name == include)
                    .unwrap_or(0);
                let mut cycle = stack[position..]
                    .iter()
                    .map(|ancestor| ancestor.name.clone())
                    .collect::<Vec<_>>();
                cycle.push(include.to_owned());
                return Err(manifest_error(
                    path,
                    format!(
                        "Python dependency-group include cycle: {}",
                        cycle.join(" -> ")
                    ),
                ));
            }

            stack.push(GroupFrame {
                name: include.to_owned(),
                next_entry: 0,
            });
            active.insert(include.to_owned());
        }
    }
    Ok(())
}

fn parse_poetry_dependencies(
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

fn poetry_dependency(path: &Path, name: &str, spec: &TomlValue) -> Result<Dependency> {
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

fn poetry_requirement(path: &Path, name: &str, spec: &TomlValue) -> Result<String> {
    if let Some(version) = spec.as_str() {
        return requirement_with_poetry_constraint(path, name, version);
    }

    let table = spec
        .as_table()
        .expect("Poetry dependency entry type was validated before building its requirement");
    if let Some(url) = table.get("url").and_then(TomlValue::as_str) {
        Ok(format!("{name} @ {url}"))
    } else if let Some(path) = table.get("path").and_then(TomlValue::as_str) {
        Ok(format!("file:{path}"))
    } else if let Some(git) = table.get("git").and_then(TomlValue::as_str) {
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

pub(super) fn dependency_from_requirement(requirement: &str) -> Dependency {
    let before_marker = requirement.split(';').next().unwrap_or(requirement).trim();
    let name = before_marker
        .split(['<', '>', '=', '!', '~', '[', ' ', '@'])
        .next()
        .unwrap_or(before_marker)
        .trim();
    let canonical_name = normalize(name);
    let canonical_requirement = requirement.strip_prefix(name).map_or_else(
        || requirement.to_owned(),
        |suffix| format!("{canonical_name}{suffix}"),
    );
    let canonical_source_requirement = before_marker.strip_prefix(name).map_or_else(
        || before_marker.to_owned(),
        |suffix| format!("{canonical_name}{suffix}"),
    );
    let mut dependency = declared_dependency(
        &canonical_name,
        &canonical_requirement,
        &canonical_source_requirement,
    );
    if dependency.source_url.is_none()
        && let Some((_, url)) = before_marker.split_once('@')
    {
        dependency.source_url = Some(url.trim().to_owned());
    }
    dependency
}

fn declared_dependency(name: &str, requirement: &str, source_requirement: &str) -> Dependency {
    let mut dependency = Dependency::declared(Ecosystem::Python, normalize(name), requirement);
    if let Some((archive, commit)) = github_archive(source_requirement) {
        dependency.resolved_version = Some(commit);
        dependency.source_url = Some(archive);
    }
    dependency
}

#[cfg(test)]
mod tests;
