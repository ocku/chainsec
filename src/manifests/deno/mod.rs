use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use super::shared::{
    ManifestRoot, extend_dependencies_bounded, is_file_beneath, manifest_error, read, read_beneath,
};
use crate::{
    error::Result,
    model::{Dependency, EngineLimits},
};

mod config;
mod import_map;
mod jsonc;
mod lockfile;
mod package_json;
mod paths;
mod workspace;

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(super) fn strip_jsonc(input: &str) -> std::result::Result<String, String> {
    jsonc::strip_jsonc(input)
}

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

#[cfg(test)]
pub(super) fn parse(root: &Path, path: &Path) -> Result<ParsedDeno> {
    parse_with_limits(root, path, &EngineLimits::default())
}

pub(super) fn parse_with_limits(
    root: &Path,
    path: &Path,
    limits: &EngineLimits,
) -> Result<ParsedDeno> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| manifest_error(path, "Deno manifest must be within its discovery root"))?
        .to_path_buf();
    let mut active = HashSet::from([relative.clone()]);
    let root_document = config::parse_config_document(
        path,
        &read(path)?,
        root,
        &relative,
        &mut active,
        (0, limits.max_package_depth),
        None,
    )?;
    let root_package_catalogs = root_package_catalogs(root)?;
    let catalogs = root_package_catalogs
        .as_ref()
        .unwrap_or(&root_document.catalogs);

    let mut dependencies = Vec::new();
    extend_dependencies_bounded(
        &mut dependencies,
        import_map::mappings_to_dependencies(&root_document.mappings),
        limits.max_packages,
    )?;
    let Some(workspace_patterns) = root_document.workspace.as_deref() else {
        return Ok(ParsedDeno {
            dependencies,
            lockfile: root_document.lockfile,
        });
    };

    let members = workspace::expand_workspace_members(
        root,
        path,
        workspace_patterns,
        limits.max_package_depth,
        limits.max_source_files,
        limits.max_packages,
    )?;
    for member in members {
        let member = workspace::parse_workspace_member(
            root,
            path,
            &member,
            catalogs,
            root_document.uses_external_import_map,
            limits.max_package_depth,
            limits.max_packages,
        )?;
        extend_dependencies_bounded(
            &mut dependencies,
            import_map::mappings_to_dependencies(&member.mappings),
            limits.max_packages,
        )?;
        extend_dependencies_bounded(&mut dependencies, member.dependencies, limits.max_packages)?;
    }
    Ok(ParsedDeno {
        dependencies,
        lockfile: root_document.lockfile,
    })
}

fn root_package_catalogs(
    root: &Path,
) -> Result<Option<std::collections::HashMap<String, std::collections::HashMap<String, String>>>> {
    let relative = Path::new("package.json");
    if !is_file_beneath(root, relative)? {
        return Ok(None);
    }
    let path = root.join(relative);
    package_json::parse_package_json_catalogs(&path, &read_beneath(root, relative)?)
}

pub(super) fn enrich(
    root: &Path,
    selection: &LockfileSelection,
    dependencies: &mut [Dependency],
    lockfiles: &mut Vec<PathBuf>,
    limits: &EngineLimits,
) -> Result<()> {
    lockfile::enrich(
        root,
        selection,
        dependencies,
        lockfiles,
        limits.max_redirect_hops,
    )
}
