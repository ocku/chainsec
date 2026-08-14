use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use serde_json::Value as JsonValue;

use super::{
    LockfileSelection,
    import_map::{ImportMappings, parse_mappings},
    package_json::parse_catalogs,
    paths::parse_lockfile_selection,
};
use crate::{error::Result, manifests::shared::manifest_error};

#[derive(Debug)]
pub(super) struct ConfigDocument {
    pub(super) mappings: ImportMappings,
    pub(super) catalogs: HashMap<String, HashMap<String, String>>,
    pub(super) catalogs_configured: bool,
    pub(super) workspace: Option<Vec<String>>,
    pub(super) lockfile: LockfileSelection,
    pub(super) lockfile_configured: bool,
    pub(super) uses_external_import_map: bool,
}

pub(super) fn parse_config_document(
    path: &Path,
    contents: &str,
    root: &Path,
    relative: &Path,
    active: &mut HashSet<PathBuf>,
    depth: (usize, usize),
    catalogs: Option<&HashMap<String, HashMap<String, String>>>,
) -> Result<ConfigDocument> {
    let clean =
        super::jsonc::strip_jsonc(contents).map_err(|message| manifest_error(path, message))?;
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

    let (mappings, uses_external_import_map) = parse_mappings(
        path,
        object,
        root,
        relative,
        active,
        depth,
        "Deno manifest importMap must be a string",
        catalogs,
    )?;

    Ok(ConfigDocument {
        mappings,
        catalogs: parse_catalogs(path, object)?,
        catalogs_configured: object.contains_key("catalog") || object.contains_key("catalogs"),
        workspace: super::workspace::parse_workspace(path, object.get("workspace"))?,
        lockfile: parse_lockfile_selection(path, relative, object.get("lock"))?,
        lockfile_configured: object.contains_key("lock"),
        uses_external_import_map,
    })
}
