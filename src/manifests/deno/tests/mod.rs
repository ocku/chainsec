use std::{fs, path::Path};

use serde_json::{Value as JsonValue, json};
use tempfile::tempdir;

use super::{
    LockfileSelection, enrich as enrich_with_limits, import_map,
    jsonc::strip_jsonc,
    lockfile::{
        LockVersion, enrich_dependency, enrich_dependency_with_redirect_limit,
        validate_lockfile_version,
    },
    parse, parse_with_limits, select_manifest,
};
use crate::{
    manifests::shared::{ManifestRoot, with_manifest_roots},
    model::{Dependency, Ecosystem, EngineLimits},
};

fn dependency(requirement: &str) -> Dependency {
    Dependency::declared(Ecosystem::Deno, "fixture", requirement)
}

fn enrich(
    root: &Path,
    selection: &LockfileSelection,
    dependencies: &mut [Dependency],
    lockfiles: &mut Vec<std::path::PathBuf>,
) -> crate::Result<()> {
    enrich_with_limits(
        root,
        selection,
        dependencies,
        lockfiles,
        &EngineLimits::default(),
    )
}

fn parse_manifest(root: &Path) -> super::ParsedDeno {
    parse(root, &root.join("deno.json")).unwrap()
}

mod config_import_maps;
mod jsonc;
mod lockfiles;
mod package_json;
mod workspaces;
