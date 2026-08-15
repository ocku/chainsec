use std::{
    collections::HashMap,
    path::{Component, Path, PathBuf},
};

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use serde_json::Value as JsonValue;

use super::{
    config::{ConfigDocument, parse_config_document},
    import_map::ImportMappings,
    package_json::parse_package_json_dependencies,
};
use crate::model::Dependency;
use crate::{
    error::Result,
    manifests::shared::{
        RootedFileType, is_file_beneath, manifest_error, push_workspace_member_bounded,
        read_beneath, walk_workspace_beneath, workspace_depth_exceeded,
        workspace_pattern_may_match_descendant,
    },
};

pub(super) fn parse_workspace(
    path: &Path,
    value: Option<&JsonValue>,
) -> Result<Option<Vec<String>>> {
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

pub(super) struct WorkspaceMember {
    pub(super) mappings: ImportMappings,
    pub(super) dependencies: Vec<Dependency>,
    pub(super) package_manifest: Option<PathBuf>,
}

pub(super) fn parse_workspace_member(
    root: &Path,
    workspace_manifest: &Path,
    member: &Path,
    catalogs: &HashMap<String, HashMap<String, String>>,
    inherited_external_import_map: bool,
    max_package_depth: usize,
    max_packages: usize,
) -> Result<WorkspaceMember> {
    let mut mappings = ImportMappings::default();
    let mut dependencies = Vec::new();
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
        let mut active = std::collections::HashSet::from([relative.clone()]);
        let document = parse_config_document(
            &path,
            &contents,
            root,
            &relative,
            &mut active,
            (0, max_package_depth),
            Some(catalogs),
        )?;
        validate_member_document(&path, &document, inherited_external_import_map)?;
        mappings.imports.extend(document.mappings.imports);
        mappings.scoped.extend(document.mappings.scoped);
    }
    let package_json = member.join("package.json");
    let has_package_json = is_file_beneath(root, &package_json)?;
    let package_manifest = has_package_json.then(|| root.join(&package_json));
    if let Some(path) = package_manifest.as_ref() {
        let contents = read_beneath(root, &package_json)?;
        dependencies.extend(parse_package_json_dependencies(
            path,
            &contents,
            catalogs,
            max_packages,
        )?);
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
    Ok(WorkspaceMember {
        mappings,
        dependencies,
        package_manifest,
    })
}

fn validate_member_document(
    path: &Path,
    document: &ConfigDocument,
    inherited_external_import_map: bool,
) -> Result<()> {
    if document.workspace.is_some() {
        return Err(manifest_error(
            path,
            "nested Deno workspaces are unsupported",
        ));
    }
    if document.lockfile_configured {
        return Err(manifest_error(
            path,
            "Deno workspace member may not configure a lockfile",
        ));
    }
    if document.catalogs_configured {
        return Err(manifest_error(
            path,
            "Deno workspace member may not configure catalogs",
        ));
    }
    if inherited_external_import_map
        && (!document.mappings.imports.is_empty() || !document.mappings.scoped.is_empty())
    {
        return Err(manifest_error(
            path,
            "Deno workspace member imports cannot be combined with a root external importMap",
        ));
    }
    Ok(())
}

pub(super) fn expand_workspace_members(
    root: &Path,
    manifest: &Path,
    patterns: &[String],
    max_package_depth: usize,
    max_entries: u64,
    max_members: usize,
) -> Result<Vec<PathBuf>> {
    let (includes, excludes) = workspace_globs(manifest, patterns)?;
    let mut members = Vec::new();
    walk_workspace_beneath(
        root,
        max_package_depth,
        max_entries,
        &mut |entry, depth, kind| {
            if workspace_depth_exceeded(
                kind,
                depth,
                max_package_depth,
                (includes.is_match(entry) && !excludes.is_match(entry))
                    || workspace_pattern_may_match_descendant(patterns, entry),
            ) {
                return Err(crate::error::Error::LimitExceeded {
                    resource: "workspace depth".to_owned(),
                    limit: u64::try_from(max_package_depth).unwrap_or(u64::MAX),
                });
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
                push_workspace_member_bounded(&mut members, relative.to_path_buf(), max_members)?;
            }
            Ok(())
        },
    )?;
    members.sort();
    members.dedup();
    Ok(members)
}

fn workspace_globs(manifest: &Path, patterns: &[String]) -> Result<(GlobSet, GlobSet)> {
    let mut includes = GlobSetBuilder::new();
    let mut excludes = GlobSetBuilder::new();
    let mut include_count = 0usize;
    for raw in patterns {
        let (exclude, pattern) = raw
            .strip_prefix('!')
            .map_or((false, raw.as_str()), |pattern| (true, pattern));
        let pattern = pattern.strip_prefix("./").unwrap_or(pattern);
        validate_workspace_pattern(manifest, pattern)?;
        let glob = GlobBuilder::new(pattern)
            .literal_separator(true)
            .build()
            .map_err(|error| {
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
