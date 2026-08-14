use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use serde_json::Value as JsonValue;

use super::{package_json::resolve_catalog_requirement, paths::local_path};
use crate::{
    error::Result,
    manifests::shared::{manifest_error, read_beneath},
    model::{Dependency, Ecosystem, canonical_http_url},
};

#[derive(Clone, Debug, Default)]
pub(crate) struct ImportMappings {
    pub(crate) imports: HashMap<String, String>,
    pub(crate) scoped: Vec<(String, String)>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn parse_mappings(
    path: &Path,
    object: &serde_json::Map<String, JsonValue>,
    root: &Path,
    relative: &Path,
    active: &mut HashSet<PathBuf>,
    depth: (usize, usize),
    import_map_error: &str,
    catalogs: Option<&HashMap<String, HashMap<String, String>>>,
) -> Result<(ImportMappings, bool)> {
    let Some(import_map) = object.get("importMap") else {
        return collect_mappings(path, object, catalogs).map(|mappings| (mappings, false));
    };
    let import_map = import_map
        .as_str()
        .ok_or_else(|| manifest_error(path, import_map_error))?;
    if depth.0 >= depth.1 {
        return Err(manifest_error(
            path,
            format!(
                "Deno external importMap chain reaches the {}-level depth limit",
                depth.1
            ),
        ));
    }

    let import_map_relative = local_path(path, relative, import_map, "importMap")?;
    if !active.insert(import_map_relative.clone()) {
        return Err(manifest_error(
            path,
            "cycle detected in Deno external importMap references",
        ));
    }
    let import_map_path = root.join(&import_map_relative);
    let contents = read_beneath(root, &import_map_relative)?;
    let result = parse_import_map(
        &import_map_path,
        &contents,
        root,
        &import_map_relative,
        active,
        (depth.0 + 1, depth.1),
        catalogs,
    );
    active.remove(&import_map_relative);
    result.map(|mappings| (mappings, true))
}

fn parse_import_map(
    path: &Path,
    contents: &str,
    root: &Path,
    relative: &Path,
    active: &mut HashSet<PathBuf>,
    depth: (usize, usize),
    catalogs: Option<&HashMap<String, HashMap<String, String>>>,
) -> Result<ImportMappings> {
    let clean =
        super::jsonc::strip_jsonc(contents).map_err(|message| manifest_error(path, message))?;
    let value: JsonValue =
        serde_json::from_str(&clean).map_err(|error| manifest_error(path, error))?;
    let object = value
        .as_object()
        .ok_or_else(|| manifest_error(path, "Deno import map root must be an object"))?;
    if let Some(import_map) = object.get("importMap") {
        import_map
            .as_str()
            .ok_or_else(|| manifest_error(path, "Deno importMap must be a string"))?;
        if object.contains_key("imports") || object.contains_key("scopes") {
            return Err(manifest_error(
                path,
                "nested importMap cannot be combined with imports or scopes",
            ));
        }
    }
    parse_mappings(
        path,
        object,
        root,
        relative,
        active,
        depth,
        "Deno importMap must be a string",
        catalogs,
    )
    .map(|(mappings, _)| mappings)
}

fn collect_mappings(
    path: &Path,
    object: &serde_json::Map<String, JsonValue>,
    catalogs: Option<&HashMap<String, HashMap<String, String>>>,
) -> Result<ImportMappings> {
    let mut mappings = ImportMappings::default();
    if let Some(imports) = object.get("imports") {
        let entries = imports
            .as_object()
            .ok_or_else(|| manifest_error(path, "Deno manifest imports must be an object"))?;
        collect_entries(path, entries, catalogs, |name, requirement| {
            mappings
                .imports
                .insert(name.to_owned(), requirement.to_owned());
        })?;
    }
    if let Some(scopes) = object.get("scopes") {
        let scopes = scopes
            .as_object()
            .ok_or_else(|| manifest_error(path, "Deno manifest scopes must be an object"))?;
        for (scope, entries) in scopes {
            let entries = entries.as_object().ok_or_else(|| {
                manifest_error(
                    path,
                    format!("Deno manifest scope {scope} must be an object"),
                )
            })?;
            collect_entries(path, entries, catalogs, |name, requirement| {
                mappings
                    .scoped
                    .push((name.to_owned(), requirement.to_owned()))
            })?;
        }
    }

    Ok(mappings)
}

fn collect_entries(
    path: &Path,
    entries: &serde_json::Map<String, JsonValue>,
    catalogs: Option<&HashMap<String, HashMap<String, String>>>,
    mut collect: impl FnMut(&str, &str),
) -> Result<()> {
    for (name, value) in entries {
        let requirement = value.as_str().ok_or_else(|| {
            manifest_error(path, format!("Deno manifest entry {name} must be a string"))
        })?;
        let requirement = if requirement.starts_with("catalog:") {
            let catalogs = catalogs.ok_or_else(|| {
                manifest_error(
                    path,
                    "Deno catalog imports are only supported in workspace members",
                )
            })?;
            format!(
                "npm:{name}@{}",
                resolve_catalog_requirement(path, name, requirement, catalogs)?
            )
        } else {
            requirement.to_owned()
        };
        if is_fetchable_requirement(&requirement) {
            collect(name, &requirement);
        }
    }
    Ok(())
}

fn is_fetchable_requirement(requirement: &str) -> bool {
    requirement.starts_with("npm:")
        || requirement.starts_with("jsr:")
        || canonical_http_url(requirement).is_some()
}

pub(crate) fn mappings_to_dependencies(
    mappings: &ImportMappings,
) -> impl Iterator<Item = Dependency> + '_ {
    mappings
        .imports
        .iter()
        .chain(mappings.scoped.iter().map(|(name, value)| (name, value)))
        .map(|(name, requirement)| {
            let requirement = normalize_npm_subpath(&normalize_jsr_subpath(requirement));
            let mut dependency = Dependency::declared(Ecosystem::Deno, name, &requirement);
            if canonical_http_url(&requirement).is_some() {
                dependency.source_url = Some(requirement.to_owned());
            }
            dependency
        })
}

pub(crate) fn normalize_npm_subpath(requirement: &str) -> String {
    normalize_registry_subpath(requirement, "npm:")
}

pub(crate) fn normalize_jsr_subpath(requirement: &str) -> String {
    normalize_registry_subpath(requirement, "jsr:")
}

fn normalize_registry_subpath(requirement: &str, scheme: &str) -> String {
    let Some(specifier) = requirement.strip_prefix(scheme) else {
        return requirement.to_owned();
    };
    // External import maps may use URL-style registry specifiers (`jsr:/@scope/pkg`).
    let specifier = specifier.strip_prefix('/').unwrap_or(specifier);
    let package_end = if let Some(scoped) = specifier.strip_prefix('@') {
        let Some(scope_end) = scoped.find('/') else {
            return requirement.to_owned();
        };
        let package_start = scope_end + 2;
        scoped[scope_end + 1..]
            .find(['@', '/'])
            .map(|offset| package_start + offset)
    } else {
        specifier.find(['@', '/'])
    };
    let Some(package_end) = package_end else {
        return requirement.to_owned();
    };
    let package = &specifier[..package_end];
    let suffix = &specifier[package_end..];
    let version = suffix
        .strip_prefix('@')
        .map(|version_and_subpath| version_and_subpath.split('/').next().unwrap_or_default())
        .filter(|version| !version.is_empty());
    match version {
        Some(version) => format!("{scheme}{package}@{version}"),
        None => format!("{scheme}{package}"),
    }
}
