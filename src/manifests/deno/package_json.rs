use std::{collections::HashMap, path::Path};

use crate::{
    error::Result,
    manifests::shared::{github_archive, manifest_error, package_json_dependencies},
    model::{Dependency, Ecosystem, canonical_http_url},
};
use serde_json::Value as JsonValue;

pub(super) fn parse_catalogs(
    path: &Path,
    object: &serde_json::Map<String, JsonValue>,
) -> Result<HashMap<String, HashMap<String, String>>> {
    let mut catalogs = HashMap::new();
    if let Some(catalog) = object.get("catalog") {
        catalogs.insert(
            "default".to_owned(),
            parse_catalog(path, "catalog", catalog)?,
        );
    }
    if let Some(named) = object.get("catalogs") {
        let named = named
            .as_object()
            .ok_or_else(|| manifest_error(path, "Deno catalogs must be an object"))?;
        for (name, catalog) in named {
            catalogs.insert(
                name.clone(),
                parse_catalog(path, &format!("catalogs.{name}"), catalog)?,
            );
        }
    }
    Ok(catalogs)
}

fn parse_catalog(path: &Path, section: &str, value: &JsonValue) -> Result<HashMap<String, String>> {
    let entries = value
        .as_object()
        .ok_or_else(|| manifest_error(path, format!("Deno {section} must be an object")))?;
    entries
        .iter()
        .map(|(name, version)| {
            version
                .as_str()
                .map(|version| (name.clone(), version.to_owned()))
                .ok_or_else(|| {
                    manifest_error(path, format!("Deno {section}.{name} must be a string"))
                })
        })
        .collect()
}

pub(super) fn parse_package_json_catalogs(
    path: &Path,
    contents: &str,
) -> Result<Option<HashMap<String, HashMap<String, String>>>> {
    let Ok(value) = serde_json::from_str::<JsonValue>(contents) else {
        // The npm manifest parser reports malformed package.json files. Do not duplicate that
        // error while checking whether Deno workspace catalogs override deno.json catalogs.
        return Ok(None);
    };
    let Some(package) = value.as_object() else {
        return Ok(None);
    };
    if !package.contains_key("catalog") && !package.contains_key("catalogs") {
        return Ok(None);
    }
    parse_catalogs(path, package).map(Some)
}

pub(super) fn parse_package_json_dependencies(
    path: &Path,
    contents: &str,
    catalogs: &HashMap<String, HashMap<String, String>>,
    max_packages: usize,
) -> Result<Vec<Dependency>> {
    let value: JsonValue =
        serde_json::from_str(contents).map_err(|error| manifest_error(path, error))?;
    let package = value
        .as_object()
        .ok_or_else(|| manifest_error(path, "package.json root must be an object"))?;
    package_json_dependencies(path, package, max_packages)?
        .into_iter()
        .filter(|(_, requirement)| !is_local_package_requirement(requirement))
        .map(|(name, requirement)| {
            let requirement = resolve_catalog_requirement(path, &name, &requirement, catalogs)?;
            Ok(package_dependency(&name, &requirement))
        })
        .collect()
}

fn package_dependency(name: &str, requirement: &str) -> Dependency {
    let mut dependency = Dependency::declared(Ecosystem::Deno, name, requirement);
    if let Some((archive, commit)) = github_archive(requirement) {
        dependency.resolved_version = Some(commit);
        dependency.source_url = Some(archive);
        return dependency;
    }
    if canonical_http_url(requirement).is_some() {
        dependency.source_url = Some(requirement.to_owned());
        return dependency;
    }
    if requirement.starts_with("npm:")
        || requirement.starts_with("jsr:")
        || is_non_registry_package_requirement(requirement)
    {
        return dependency;
    }
    dependency.requirement = format!("npm:{name}@{requirement}");
    dependency
}

fn is_non_registry_package_requirement(requirement: &str) -> bool {
    [
        "github:",
        "gitlab:",
        "bitbucket:",
        "gist:",
        "git+",
        "git://",
        "git@",
        "ssh://",
    ]
    .into_iter()
    .any(|prefix| {
        requirement
            .get(..prefix.len())
            .is_some_and(|actual| actual.eq_ignore_ascii_case(prefix))
    })
}

pub(super) fn resolve_catalog_requirement(
    path: &Path,
    package: &str,
    requirement: &str,
    catalogs: &HashMap<String, HashMap<String, String>>,
) -> Result<String> {
    let Some(catalog) = requirement.strip_prefix("catalog:") else {
        return Ok(requirement.to_owned());
    };
    let catalog = if catalog.is_empty() {
        "default"
    } else {
        catalog
    };
    let version = catalogs
        .get(catalog)
        .and_then(|entries| entries.get(package))
        .ok_or_else(|| {
            manifest_error(
                path,
                format!("Deno catalog {catalog} does not define package {package}"),
            )
        })?;
    Ok(version.to_owned())
}

fn is_local_package_requirement(requirement: &str) -> bool {
    ["workspace:", "file:", "link:", "portal:", "./", "../"]
        .into_iter()
        .any(|prefix| requirement.starts_with(prefix))
        || Path::new(requirement).is_absolute()
}
