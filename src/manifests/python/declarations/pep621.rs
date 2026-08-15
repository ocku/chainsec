use std::{collections::HashSet, path::Path};

use toml::Value as TomlValue;

use super::shared::dependency_from_requirement;
use crate::{
    error::Result,
    manifests::shared::{BoundedDependencyCollector, manifest_error},
};

pub(super) fn parse_project_dependencies(
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

pub(super) fn parse_dependency_groups(
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
