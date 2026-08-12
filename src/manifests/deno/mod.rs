use std::{
    collections::{HashMap, HashSet},
    path::{Component, Path, PathBuf},
};

use super::shared::{
    ManifestRoot, RootedFileType, is_file_beneath, manifest_error, read, read_beneath, walk_beneath,
};
use crate::{
    error::Result,
    model::{Dependency, Ecosystem},
};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde_json::Value as JsonValue;

mod jsonc;
mod lockfile;

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(super) fn strip_jsonc(input: &str) -> std::result::Result<String, String> {
    jsonc::strip_jsonc(input)
}

const MAX_EXTERNAL_IMPORT_MAP_DEPTH: usize = 32;
const MAX_WORKSPACE_DEPTH: usize = 32;
const MAX_WORKSPACE_ENTRIES: usize = 4096;
const MAX_WORKSPACE_MEMBERS: usize = 256;
const MAX_WORKSPACE_PATTERNS: usize = 4096;
const MAX_IMPORT_MAPPINGS: usize = 16_384;
const MAX_DISCOVERED_DEPENDENCIES: usize = 16_384;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum LockfileSelection {
    Disabled,
    Path(PathBuf),
}

#[derive(Debug)]
pub(super) struct ParsedDeno {
    pub(super) dependencies: Vec<Dependency>,
    pub(super) lockfile: LockfileSelection,
}

#[derive(Clone, Debug, Default)]
struct ImportMappings {
    imports: HashMap<String, String>,
    scoped: Vec<(String, String)>,
}

#[derive(Debug)]
struct ConfigDocument {
    mappings: ImportMappings,
    catalogs: HashMap<String, HashMap<String, String>>,
    workspace: Option<Vec<String>>,
    lockfile: LockfileSelection,
    lockfile_configured: bool,
    uses_external_import_map: bool,
}

impl Default for LockfileSelection {
    fn default() -> Self {
        Self::Path(PathBuf::from("deno.lock"))
    }
}

pub(super) fn select_manifest(root: &ManifestRoot) -> Result<Option<PathBuf>> {
    let directory = root.path();
    let json = directory.join("deno.json");
    let jsonc = directory.join("deno.jsonc");
    match (
        root.is_file(Path::new("deno.json"))?,
        root.is_file(Path::new("deno.jsonc"))?,
    ) {
        (true, true) => Err(manifest_error(
            directory,
            "both deno.json and deno.jsonc exist; refusing ambiguous Deno configuration",
        )),
        (true, false) => Ok(Some(json)),
        (false, true) => Ok(Some(jsonc)),
        (false, false) => Ok(None),
    }
}

pub(super) fn parse(root: &Path, path: &Path) -> Result<ParsedDeno> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| manifest_error(path, "Deno manifest must be within its discovery root"))?
        .to_path_buf();
    let mut active = HashSet::from([relative.clone()]);
    let root_document = parse_config_document(path, &read(path)?, root, &relative, &mut active, 0)?;

    let mut dependencies = mappings_to_dependencies(&root_document.mappings);
    ensure_dependency_limit(path, dependencies.len())?;
    let Some(workspace_patterns) = root_document.workspace.as_deref() else {
        return Ok(ParsedDeno {
            dependencies,
            lockfile: root_document.lockfile,
        });
    };

    let members = expand_workspace_members(root, path, workspace_patterns)?;
    for member in members {
        let member_mappings = parse_workspace_member(
            root,
            path,
            &member,
            &root_document.mappings,
            &root_document.catalogs,
            root_document.uses_external_import_map,
        )?;
        let member_dependencies = mappings_to_dependencies(&member_mappings);
        ensure_dependency_limit(path, dependencies.len() + member_dependencies.len())?;
        dependencies.extend(member_dependencies);
    }

    Ok(ParsedDeno {
        dependencies,
        lockfile: root_document.lockfile,
    })
}

fn parse_workspace_member(
    root: &Path,
    workspace_manifest: &Path,
    member: &Path,
    inherited: &ImportMappings,
    catalogs: &HashMap<String, HashMap<String, String>>,
    inherited_external_import_map: bool,
) -> Result<ImportMappings> {
    let mut mappings = inherited.clone();
    let deno_json = member.join("deno.json");
    let deno_jsonc = member.join("deno.jsonc");
    let has_json = is_file_beneath(root, &deno_json)?;
    let has_jsonc = is_file_beneath(root, &deno_jsonc)?;
    let member_manifest = match (has_json, has_jsonc) {
        (true, true) => {
            return Err(manifest_error(
                &root.join(member),
                "both deno.json and deno.jsonc exist in Deno workspace member",
            ));
        }
        (true, false) => Some(deno_json),
        (false, true) => Some(deno_jsonc),
        (false, false) => None,
    };

    if let Some(relative) = member_manifest {
        let path = root.join(&relative);
        let contents = read_beneath(root, &relative)?;
        let mut active = HashSet::from([relative.clone()]);
        let document = parse_config_document(&path, &contents, root, &relative, &mut active, 0)?;
        if document.workspace.is_some() {
            return Err(manifest_error(
                &path,
                "nested Deno workspaces are unsupported",
            ));
        }
        if document.lockfile_configured {
            return Err(manifest_error(
                &path,
                "Deno workspace member may not configure a lockfile",
            ));
        }
        if inherited_external_import_map
            && (!document.mappings.imports.is_empty() || !document.mappings.scoped.is_empty())
        {
            return Err(manifest_error(
                &path,
                "Deno workspace member imports cannot be combined with a root external importMap",
            ));
        }
        mappings.imports.extend(document.mappings.imports);
        mappings.scoped.extend(document.mappings.scoped);
    }

    let package_json = member.join("package.json");
    let has_package_json = is_file_beneath(root, &package_json)?;
    if has_package_json {
        let path = root.join(&package_json);
        let contents = read_beneath(root, &package_json)?;
        mappings
            .scoped
            .extend(parse_package_json_dependencies(&path, &contents, catalogs)?);
    }

    if member != Path::new("") && !has_json && !has_jsonc && !has_package_json {
        return Err(manifest_error(
            workspace_manifest,
            format!(
                "Deno workspace member {} has no deno.json, deno.jsonc, or package.json",
                member.display()
            ),
        ));
    }

    Ok(mappings)
}

fn parse_config_document(
    path: &Path,
    contents: &str,
    root: &Path,
    relative: &Path,
    active: &mut HashSet<PathBuf>,
    depth: usize,
) -> Result<ConfigDocument> {
    let clean = jsonc::strip_jsonc(contents).map_err(|message| manifest_error(path, message))?;
    let value: JsonValue =
        serde_json::from_str(&clean).map_err(|error| manifest_error(path, error))?;
    let object = value
        .as_object()
        .ok_or_else(|| manifest_error(path, "Deno manifest root must be an object"))?;

    let has_inline_mappings = object.contains_key("imports") || object.contains_key("scopes");
    if object.contains_key("importMap") && has_inline_mappings {
        return Err(manifest_error(
            path,
            "Deno manifest importMap cannot be combined with inline imports or scopes",
        ));
    }

    let (mappings, uses_external_import_map) = if let Some(import_map) = object.get("importMap") {
        let import_map = import_map
            .as_str()
            .ok_or_else(|| manifest_error(path, "Deno manifest importMap must be a string"))?;
        if depth >= MAX_EXTERNAL_IMPORT_MAP_DEPTH {
            return Err(manifest_error(
                path,
                format!(
                    "Deno external importMap recursion exceeds the {MAX_EXTERNAL_IMPORT_MAP_DEPTH}-map limit"
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
            depth + 1,
        );
        active.remove(&import_map_relative);
        (result?, true)
    } else {
        (collect_mappings(path, object)?, false)
    };

    Ok(ConfigDocument {
        mappings,
        catalogs: parse_catalogs(path, object)?,
        workspace: parse_workspace(path, object.get("workspace"))?,
        lockfile: parse_lockfile_selection(path, relative, object.get("lock"))?,
        lockfile_configured: object.contains_key("lock"),
        uses_external_import_map,
    })
}

fn parse_import_map(
    path: &Path,
    contents: &str,
    root: &Path,
    relative: &Path,
    active: &mut HashSet<PathBuf>,
    depth: usize,
) -> Result<ImportMappings> {
    let clean = jsonc::strip_jsonc(contents).map_err(|message| manifest_error(path, message))?;
    let value: JsonValue =
        serde_json::from_str(&clean).map_err(|error| manifest_error(path, error))?;
    let object = value
        .as_object()
        .ok_or_else(|| manifest_error(path, "Deno import map root must be an object"))?;
    if let Some(nested) = object.get("importMap") {
        let nested = nested
            .as_str()
            .ok_or_else(|| manifest_error(path, "Deno importMap must be a string"))?;
        if object.contains_key("imports") || object.contains_key("scopes") {
            return Err(manifest_error(
                path,
                "nested importMap cannot be combined with imports or scopes",
            ));
        }
        if depth >= MAX_EXTERNAL_IMPORT_MAP_DEPTH {
            return Err(manifest_error(
                path,
                format!(
                    "Deno external importMap recursion exceeds the {MAX_EXTERNAL_IMPORT_MAP_DEPTH}-map limit"
                ),
            ));
        }
        let nested_relative = local_path(path, relative, nested, "importMap")?;
        if !active.insert(nested_relative.clone()) {
            return Err(manifest_error(
                path,
                "cycle detected in Deno external importMap references",
            ));
        }
        let nested_path = root.join(&nested_relative);
        let contents = read_beneath(root, &nested_relative)?;
        let result = parse_import_map(
            &nested_path,
            &contents,
            root,
            &nested_relative,
            active,
            depth + 1,
        );
        active.remove(&nested_relative);
        return result;
    }
    collect_mappings(path, object)
}

fn collect_mappings(
    path: &Path,
    object: &serde_json::Map<String, JsonValue>,
) -> Result<ImportMappings> {
    let mut mappings = ImportMappings::default();
    if let Some(imports) = object.get("imports") {
        let entries = imports
            .as_object()
            .ok_or_else(|| manifest_error(path, "Deno manifest imports must be an object"))?;
        collect_entries(path, entries, |name, requirement| {
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
            collect_entries(path, entries, |name, requirement| {
                mappings
                    .scoped
                    .push((name.to_owned(), requirement.to_owned()));
            })?;
        }
    }
    let mapping_count = mappings.imports.len() + mappings.scoped.len();
    if mapping_count > MAX_IMPORT_MAPPINGS {
        return Err(manifest_error(
            path,
            format!("Deno import mappings exceed the {MAX_IMPORT_MAPPINGS}-entry limit"),
        ));
    }
    Ok(mappings)
}

fn collect_entries(
    path: &Path,
    entries: &serde_json::Map<String, JsonValue>,
    mut collect: impl FnMut(&str, &str),
) -> Result<()> {
    for (name, value) in entries {
        let requirement = value.as_str().ok_or_else(|| {
            manifest_error(path, format!("Deno manifest entry {name} must be a string"))
        })?;
        if is_fetchable_requirement(requirement) {
            collect(name, requirement);
        }
    }
    Ok(())
}

fn is_fetchable_requirement(requirement: &str) -> bool {
    requirement.starts_with("npm:")
        || requirement.starts_with("jsr:")
        || requirement.starts_with("http://")
        || requirement.starts_with("https://")
}

fn mappings_to_dependencies(mappings: &ImportMappings) -> Vec<Dependency> {
    mappings
        .imports
        .iter()
        .chain(mappings.scoped.iter().map(|(name, value)| (name, value)))
        .map(|(name, requirement)| {
            let requirement = normalize_npm_subpath(requirement);
            let mut dependency = Dependency::declared(Ecosystem::Deno, name, &requirement);
            if requirement.starts_with("http://") || requirement.starts_with("https://") {
                dependency.source_url = Some(requirement.to_owned());
            }
            dependency
        })
        .collect()
}

fn ensure_dependency_limit(path: &Path, count: usize) -> Result<()> {
    if count > MAX_DISCOVERED_DEPENDENCIES {
        return Err(manifest_error(
            path,
            format!(
                "Deno discovered dependencies exceed the {MAX_DISCOVERED_DEPENDENCIES}-dependency limit"
            ),
        ));
    }
    Ok(())
}

pub(super) fn normalize_npm_subpath(requirement: &str) -> String {
    let Some(specifier) = requirement.strip_prefix("npm:") else {
        return requirement.to_owned();
    };
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
        Some(version) => format!("npm:{package}@{version}"),
        None => format!("npm:{package}"),
    }
}

fn parse_catalogs(
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

fn parse_package_json_dependencies(
    path: &Path,
    contents: &str,
    catalogs: &HashMap<String, HashMap<String, String>>,
) -> Result<Vec<(String, String)>> {
    let value: JsonValue =
        serde_json::from_str(contents).map_err(|error| manifest_error(path, error))?;
    let package = value
        .as_object()
        .ok_or_else(|| manifest_error(path, "package.json root must be an object"))?;
    let mut by_name = HashMap::new();
    for section in ["peerDependencies", "dependencies", "optionalDependencies"] {
        let Some(entries) = package.get(section) else {
            continue;
        };
        let entries = entries
            .as_object()
            .ok_or_else(|| manifest_error(path, format!("{section} must be an object")))?;
        for (name, requirement) in entries {
            let requirement = requirement.as_str().ok_or_else(|| {
                manifest_error(path, format!("{section}.{name} must be a string"))
            })?;
            if is_local_package_requirement(requirement) {
                continue;
            }
            let requirement = resolve_catalog_requirement(path, name, requirement, catalogs)?;
            let requirement = if requirement.starts_with("npm:") {
                requirement
            } else {
                format!("npm:{name}@{requirement}")
            };
            by_name.insert(name.clone(), requirement);
        }
    }
    Ok(by_name.into_iter().collect())
}

fn resolve_catalog_requirement(
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

fn parse_workspace(path: &Path, value: Option<&JsonValue>) -> Result<Option<Vec<String>>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let members = if let Some(members) = value.as_array() {
        members
    } else {
        value
            .as_object()
            .and_then(|workspace| workspace.get("members"))
            .and_then(JsonValue::as_array)
            .ok_or_else(|| {
                manifest_error(
                    path,
                    "Deno workspace must be an array or an object with a members array",
                )
            })?
    };
    if members.len() > MAX_WORKSPACE_PATTERNS {
        return Err(manifest_error(
            path,
            format!("Deno workspace patterns exceed the {MAX_WORKSPACE_PATTERNS}-entry limit"),
        ));
    }
    members
        .iter()
        .map(|member| {
            member
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| manifest_error(path, "Deno workspace members must be strings"))
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

fn parse_lockfile_selection(
    manifest: &Path,
    current: &Path,
    value: Option<&JsonValue>,
) -> Result<LockfileSelection> {
    let Some(value) = value else {
        return Ok(LockfileSelection::default());
    };
    match value {
        JsonValue::Bool(false) => Ok(LockfileSelection::Disabled),
        JsonValue::Bool(true) => Ok(LockfileSelection::default()),
        JsonValue::String(path) => {
            local_path(manifest, current, path, "lock path").map(LockfileSelection::Path)
        }
        JsonValue::Object(lock) => {
            if let Some(frozen) = lock.get("frozen")
                && !frozen.is_boolean()
            {
                return Err(manifest_error(
                    manifest,
                    "Deno lock.frozen must be a boolean",
                ));
            }
            match lock.get("path") {
                None => Ok(LockfileSelection::default()),
                Some(JsonValue::String(path)) => {
                    local_path(manifest, current, path, "lock path").map(LockfileSelection::Path)
                }
                Some(_) => Err(manifest_error(manifest, "Deno lock.path must be a string")),
            }
        }
        _ => Err(manifest_error(
            manifest,
            "Deno lock must be a boolean, string, or object",
        )),
    }
}

fn local_path(manifest: &Path, current: &Path, value: &str, field: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(manifest_error(
            manifest,
            format!("Deno {field} must be a local path within the discovery root"),
        ));
    }

    let mut relative = current
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .to_path_buf();
    for component in path.components() {
        if let Component::Normal(component) = component {
            relative.push(component);
        }
    }
    if relative.file_name().is_none() {
        return Err(manifest_error(
            manifest,
            format!("Deno {field} must name a local file"),
        ));
    }
    Ok(relative)
}

fn expand_workspace_members(
    root: &Path,
    manifest: &Path,
    patterns: &[String],
) -> Result<Vec<PathBuf>> {
    let (includes, excludes) = workspace_globs(manifest, patterns)?;
    let mut members = Vec::new();
    let mut entries = 0usize;
    // Keep the historical entry accounting in which the root itself counts.
    entries += 1;
    walk_beneath(root, MAX_WORKSPACE_DEPTH, &mut |entry, _depth, kind| {
        entries += 1;
        if entries > MAX_WORKSPACE_ENTRIES {
            return Err(manifest_error(
                manifest,
                format!("Deno workspace expansion exceeds the {MAX_WORKSPACE_ENTRIES}-entry limit"),
            ));
        }
        if kind == RootedFileType::Symlink {
            if includes.is_match(entry) && !excludes.is_match(entry) {
                return Err(manifest_error(
                    manifest,
                    format!(
                        "Deno workspace member {} must not be a symbolic link",
                        entry.display()
                    ),
                ));
            }
            return Ok(());
        }
        if kind != RootedFileType::File
            || !matches!(
                entry.file_name().and_then(|name| name.to_str()),
                Some("deno.json" | "deno.jsonc" | "package.json")
            )
        {
            return Ok(());
        }
        let relative = entry
            .parent()
            .ok_or_else(|| manifest_error(manifest, "workspace member escaped its root"))?;
        if includes.is_match(relative) && !excludes.is_match(relative) {
            members.push(relative.to_path_buf());
            if members.len() > MAX_WORKSPACE_MEMBERS {
                return Err(manifest_error(
                    manifest,
                    format!(
                        "Deno workspace expansion exceeds the {MAX_WORKSPACE_MEMBERS}-member limit"
                    ),
                ));
            }
        }
        Ok(())
    })?;
    members.sort();
    members.dedup();
    Ok(members)
}

fn workspace_globs(manifest: &Path, patterns: &[String]) -> Result<(GlobSet, GlobSet)> {
    if patterns.len() > MAX_WORKSPACE_PATTERNS {
        return Err(manifest_error(
            manifest,
            format!("Deno workspace patterns exceed the {MAX_WORKSPACE_PATTERNS}-entry limit"),
        ));
    }
    let mut includes = GlobSetBuilder::new();
    let mut excludes = GlobSetBuilder::new();
    let mut include_count = 0usize;
    for raw in patterns {
        let (exclude, pattern) = raw
            .strip_prefix('!')
            .map_or((false, raw.as_str()), |pattern| (true, pattern));
        let pattern = pattern.strip_prefix("./").unwrap_or(pattern);
        validate_workspace_pattern(manifest, pattern)?;
        let glob = Glob::new(pattern).map_err(|error| {
            manifest_error(manifest, format!("invalid workspace pattern: {error}"))
        })?;
        if exclude {
            excludes.add(glob);
        } else {
            includes.add(glob);
            include_count += 1;
        }
    }
    if include_count == 0 {
        return Err(manifest_error(
            manifest,
            "Deno workspace must contain at least one inclusion pattern",
        ));
    }
    Ok((
        includes
            .build()
            .map_err(|error| manifest_error(manifest, error))?,
        excludes
            .build()
            .map_err(|error| manifest_error(manifest, error))?,
    ))
}

fn validate_workspace_pattern(manifest: &Path, pattern: &str) -> Result<()> {
    let path = Path::new(pattern);
    if pattern.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(manifest_error(
            manifest,
            "Deno workspace patterns must remain within the workspace root",
        ));
    }
    Ok(())
}

pub(super) fn enrich(
    root: &Path,
    selection: &LockfileSelection,
    dependencies: &mut [Dependency],
    lockfiles: &mut Vec<PathBuf>,
) -> Result<()> {
    lockfile::enrich(root, selection, dependencies, lockfiles)
}
