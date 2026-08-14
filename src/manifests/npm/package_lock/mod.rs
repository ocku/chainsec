use std::{collections::HashMap, str::FromStr};

use node_semver::{Range as NpmRange, Version as NpmVersion};
use serde_json::Value as JsonValue;

use crate::manifests::{
    NpmLockContext,
    npm::{github_archive_matches, local_source_url, matching_github_archive},
    shared::{github_archive, manifest_error, optional_json_string, read, strip_url_fragment},
};
use crate::{error::Result, model::Dependency};

pub(super) fn enrich(
    context: &NpmLockContext,
    dependencies: &mut [Dependency],
) -> Result<HashMap<String, NpmLockContext>> {
    let path = &context.lockfile;
    let value: JsonValue =
        serde_json::from_str(&read(path)?).map_err(|error| manifest_error(path, error))?;
    let root = value
        .as_object()
        .ok_or_else(|| manifest_error(path, "package-lock.json root must be an object"))?;
    let version = match root.get("lockfileVersion") {
        Some(value) => value.as_u64().ok_or_else(|| {
            manifest_error(path, "package-lock.json lockfileVersion must be an integer")
        })?,
        None if !root.contains_key("packages")
            && root.get("dependencies").is_some_and(JsonValue::is_object) =>
        {
            1
        }
        None => {
            return Err(manifest_error(
                path,
                "package-lock.json lockfileVersion is missing outside the legacy v1 format",
            ));
        }
    };
    if !(1..=3).contains(&version) {
        return Err(manifest_error(
            path,
            format!("unsupported npm lockfile version {version}"),
        ));
    }

    let packages = optional_object(path, root, "packages")?;
    let legacy_dependencies = optional_object(path, root, "dependencies")?;
    if let Some(packages) = packages {
        validate_package_entries(path, packages, "package-lock.json packages", false)?;
    }
    if let Some(dependencies) = legacy_dependencies {
        validate_package_entries(path, dependencies, "package-lock.json dependencies", true)?;
    }
    let mut contexts = HashMap::new();
    for dependency in dependencies {
        if let Some(packages) = packages {
            let Some(importer) = packages
                .get(&context.package_path)
                .and_then(JsonValue::as_object)
            else {
                continue;
            };
            if importer_requirement(importer, &dependency.name)
                != Some(dependency.requirement.as_str())
            {
                continue;
            }
        }

        let resolved_package = packages.and_then(|packages| {
            resolve_package_path(packages, &context.package_path, &dependency.name).and_then(
                |package_path| {
                    packages
                        .get(&package_path)
                        .map(|value| (package_path, value))
                },
            )
        });
        let (package_path, package, local_reference) =
            if let Some((package_path, package)) = resolved_package {
                if !package.is_object() {
                    continue;
                }
                let (package_path, package, local_reference) =
                    resolve_linked_package(packages, package_path, package);
                if !locked_alias_identity_matches(dependency, package, local_reference.is_some()) {
                    continue;
                }
                if !locked_version_compatible(dependency, package, local_reference.is_some()) {
                    return Err(manifest_error(
                        path,
                        format!(
                            "locked version for {} does not satisfy {}",
                            dependency.name, dependency.requirement
                        ),
                    ));
                }
                (Some(package_path), package, local_reference)
            } else if version == 1 {
                let Some((package_path, package, locked_requirement)) =
                    legacy_package(legacy_dependencies, &context.package_path, &dependency.name)
                else {
                    continue;
                };
                if !legacy_requirement_matches(package, dependency, locked_requirement) {
                    continue;
                }
                (Some(package_path), package, None)
            } else {
                continue;
            };

        if let Some(reference) = local_reference {
            let reference = format!("file:{reference}");
            let Some(source_url) = local_source_url(path, &reference) else {
                continue;
            };
            dependency.resolved_version = package
                .get("version")
                .and_then(JsonValue::as_str)
                .map(str::to_owned);
            dependency.source_url = Some(source_url);
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
            continue;
        }

        let resolved = package.get("resolved").and_then(JsonValue::as_str);
        if !github_archive_matches(dependency, resolved) {
            continue;
        }
        if resolved.is_some_and(|url| url.starts_with("file:")) && !dependency.is_local() {
            continue;
        }
        if github_archive(&dependency.requirement).is_some()
            && let Some((archive, commit)) = resolved
                .and_then(github_archive)
                .or_else(|| matching_github_archive(dependency, resolved))
        {
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
            dependency.registry_integrity_required = dependency.source_url.is_none()
                && dependency.resolved_version.is_some()
                && dependency.integrity.is_none();
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

fn resolve_linked_package<'a>(
    packages: Option<&'a serde_json::Map<String, JsonValue>>,
    package_path: String,
    package: &'a JsonValue,
) -> (String, &'a JsonValue, Option<&'a str>) {
    if !package
        .get("link")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false)
    {
        return (package_path, package, None);
    }
    let Some(reference) = package.get("resolved").and_then(JsonValue::as_str) else {
        return (package_path, package, None);
    };
    let target_path = reference.strip_prefix("./").unwrap_or(reference);
    let target = packages
        .and_then(|packages| packages.get(target_path))
        .filter(|target| target.is_object())
        .unwrap_or(package);
    (target_path.to_owned(), target, Some(reference))
}

fn locked_alias_identity_matches(
    dependency: &Dependency,
    package: &JsonValue,
    local: bool,
) -> bool {
    let Some(target) = alias_target(&dependency.requirement) else {
        return true;
    };
    if local {
        return true;
    }

    // npm package-lock entries are keyed by the alias name, not the package
    // fetched by the alias. Prefer the package metadata when npm included it.
    if package
        .get("name")
        .and_then(JsonValue::as_str)
        .is_some_and(|name| name != target)
    {
        return false;
    }

    // The integrity value authenticates bytes, not package identity. When npm
    // provides a locked tarball URL, bind that artifact to the alias target as
    // well. If neither identity-bearing field is present, the alias is not
    // safe to enrich from the lockfile.
    let Some(resolved) = package.get("resolved").and_then(JsonValue::as_str) else {
        return package.get("name").and_then(JsonValue::as_str) == Some(target)
            && package
                .get("integrity")
                .and_then(JsonValue::as_str)
                .is_some();
    };
    resolved_artifact_package(resolved).as_deref() == Some(package_basename(target))
}

fn alias_target(requirement: &str) -> Option<&str> {
    requirement
        .strip_prefix("npm:")
        .and_then(|alias| alias.rsplit_once('@'))
        .map(|(target, _)| target)
        .filter(|target| !target.is_empty())
}

fn package_basename(name: &str) -> &str {
    name.rsplit_once('/').map_or(name, |(_, package)| package)
}

fn resolved_artifact_package(resolved: &str) -> Option<String> {
    let url = url::Url::parse(resolved).ok()?;
    let filename = url.path().rsplit('/').next()?.strip_suffix(".tgz")?;
    filename
        .rsplit_once('-')
        .map(|(package, _)| package.to_owned())
}

fn locked_version_compatible(dependency: &Dependency, package: &JsonValue, local: bool) -> bool {
    if local || dependency.is_local() || github_archive(&dependency.requirement).is_some() {
        return true;
    }
    let requirement = dependency
        .requirement
        .strip_prefix("npm:")
        .and_then(|alias| alias.rsplit_once('@').map(|(_, requirement)| requirement))
        .unwrap_or(&dependency.requirement);
    let Ok(range) = NpmRange::from_str(requirement) else {
        return false;
    };
    package
        .get("version")
        .and_then(JsonValue::as_str)
        .and_then(|version| NpmVersion::from_str(version).ok())
        .is_some_and(|version| range.satisfies(&version))
}

fn validate_package_entries(
    path: &std::path::Path,
    entries: &serde_json::Map<String, JsonValue>,
    context: &str,
    legacy: bool,
) -> Result<()> {
    for (name, value) in entries {
        let package = value
            .as_object()
            .ok_or_else(|| manifest_error(path, format!("{context}.{name} must be an object")))?;
        let package_context = format!("{context}.{name}");
        for field in ["name", "version", "resolved", "integrity", "from"] {
            optional_json_string(path, package, field, &package_context)?;
        }
        if let Some(link) = package.get("link")
            && !link.is_boolean()
        {
            return Err(manifest_error(
                path,
                format!("{package_context} link must be a boolean"),
            ));
        }
        if let Some(requires) = package.get("requires")
            && !requires.is_object()
        {
            return Err(manifest_error(
                path,
                format!("{package_context} requires must be an object"),
            ));
        }
        if legacy && let Some(children) = package.get("dependencies") {
            let children = children.as_object().ok_or_else(|| {
                manifest_error(
                    path,
                    format!("{package_context} dependencies must be an object"),
                )
            })?;
            validate_package_entries(
                path,
                children,
                &format!("{package_context}.dependencies"),
                true,
            )?;
        }
    }
    Ok(())
}

fn optional_object<'a>(
    path: &std::path::Path,
    root: &'a serde_json::Map<String, JsonValue>,
    field: &str,
) -> Result<Option<&'a serde_json::Map<String, JsonValue>>> {
    root.get(field)
        .map(|value| {
            value.as_object().ok_or_else(|| {
                manifest_error(path, format!("package-lock.json {field} must be an object"))
            })
        })
        .transpose()
}

fn importer_requirement<'a>(
    importer: &'a serde_json::Map<String, JsonValue>,
    name: &str,
) -> Option<&'a str> {
    [
        "optionalDependencies",
        "dependencies",
        "devDependencies",
        "peerDependencies",
    ]
    .into_iter()
    .find_map(|section| importer.get(section)?.get(name)?.as_str())
}

const LEGACY_CONTEXT_PREFIX: &str = "\0npm-lock-v1\0";

fn legacy_package<'a>(
    root_dependencies: Option<&'a serde_json::Map<String, JsonValue>>,
    package_path: &str,
    name: &str,
) -> Option<(String, &'a JsonValue, Option<&'a str>)> {
    let root_dependencies = root_dependencies?;
    let ancestry = legacy_ancestry(package_path)?;
    let locked_requirement = if ancestry.is_empty() {
        None
    } else {
        legacy_package_at(root_dependencies, &ancestry)
            .and_then(|package| package.get("requires"))
            .and_then(JsonValue::as_object)
            .and_then(|requires| requires.get(name))
            .and_then(JsonValue::as_str)
    };

    // A v1 lock represents the installed tree recursively. Prefer the package nested
    // under the importer, then walk outward to model npm's deduped/hoisted lookup.
    for depth in (0..=ancestry.len()).rev() {
        let dependencies = if depth == 0 {
            root_dependencies
        } else {
            let Some(dependencies) = legacy_package_at(root_dependencies, &ancestry[..depth])
                .and_then(|package| package.get("dependencies"))
                .and_then(JsonValue::as_object)
            else {
                continue;
            };
            dependencies
        };
        let Some(package) = dependencies.get(name).filter(|package| package.is_object()) else {
            continue;
        };
        let mut child_ancestry = ancestry[..depth].to_vec();
        child_ancestry.push(name);
        return Some((
            legacy_context_path(&child_ancestry),
            package,
            locked_requirement,
        ));
    }
    None
}

fn legacy_ancestry(package_path: &str) -> Option<Vec<&str>> {
    if package_path.is_empty() {
        Some(Vec::new())
    } else {
        package_path
            .strip_prefix(LEGACY_CONTEXT_PREFIX)
            .map(|path| path.split('\0').collect())
    }
}

fn legacy_context_path(ancestry: &[&str]) -> String {
    format!("{LEGACY_CONTEXT_PREFIX}{}", ancestry.join("\0"))
}

fn legacy_package_at<'a>(
    root_dependencies: &'a serde_json::Map<String, JsonValue>,
    ancestry: &[&str],
) -> Option<&'a JsonValue> {
    let (name, ancestors) = ancestry.split_last()?;
    let mut package = root_dependencies.get(ancestors.first().copied().unwrap_or(name))?;
    for name in ancestors
        .iter()
        .skip(1)
        .chain((!ancestors.is_empty()).then_some(name))
    {
        package = package.get("dependencies")?.get(*name)?;
    }
    Some(package)
}

fn legacy_requirement_matches(
    package: &JsonValue,
    dependency: &Dependency,
    locked_requirement: Option<&str>,
) -> bool {
    if let Some(from) = package.get("from").and_then(JsonValue::as_str) {
        return from == dependency.requirement
            || from
                .strip_prefix(&dependency.name)
                .and_then(|suffix| suffix.strip_prefix('@'))
                == Some(dependency.requirement.as_str());
    }
    if let Some(locked_requirement) = locked_requirement {
        return locked_requirement == dependency.requirement;
    }
    if dependency.is_local() {
        return package
            .get("resolved")
            .and_then(JsonValue::as_str)
            .is_some_and(|resolved| {
                resolved == dependency.requirement
                    || resolved.strip_prefix("file:") == Some(dependency.requirement.as_str())
                    || dependency.requirement.strip_prefix("file:") == Some(resolved)
            });
    }

    let Some((range, version)) = NpmRange::from_str(&dependency.requirement).ok().zip(
        package
            .get("version")
            .and_then(JsonValue::as_str)
            .and_then(|version| NpmVersion::from_str(version).ok()),
    ) else {
        return false;
    };
    range.satisfies(&version)
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

#[cfg(test)]
mod tests;
