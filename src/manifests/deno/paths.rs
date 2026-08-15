use std::path::{Component, Path, PathBuf};

use serde_json::Value as JsonValue;

use super::LockfileSelection;
use crate::{error::Result, manifests::shared::manifest_error};

pub(super) fn parse_lockfile_selection(
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

pub(super) fn local_path(
    manifest: &Path,
    current: &Path,
    value: &str,
    field: &str,
) -> Result<PathBuf> {
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
