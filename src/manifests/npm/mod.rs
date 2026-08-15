use std::{
    collections::HashMap,
    path::{Component, Path, PathBuf},
};

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

use serde_json::Value as JsonValue;

use super::{
    NpmLockContext,
    shared::{
        BoundedDependencyCollector, ManifestRoot, RootedFileType, github_archive, manifest_error,
        package_json_dependencies, push_workspace_member_bounded, read, walk_workspace_beneath,
        workspace_depth_exceeded, workspace_pattern_may_match_descendant,
    },
};
use crate::{
    error::Result,
    model::{Dependency, Ecosystem, EngineLimits},
};

mod package_lock;
mod pnpm;
mod yarn;

#[cfg(test)]
pub(super) fn parse(path: &Path) -> Result<(Vec<Dependency>, Option<Vec<String>>)> {
    parse_with_limit(path, EngineLimits::default().max_packages)
}

pub(super) fn parse_with_limit(
    path: &Path,
    max_packages: usize,
) -> Result<(Vec<Dependency>, Option<Vec<String>>)> {
    let value: JsonValue =
        serde_json::from_str(&read(path)?).map_err(|error| manifest_error(path, error))?;
    let package = value
        .as_object()
        .ok_or_else(|| manifest_error(path, "package.json root must be an object"))?;
    let install_scripts = package
        .get("scripts")
        .and_then(JsonValue::as_object)
        .map(|scripts| {
            ["preinstall", "install", "postinstall"]
                .into_iter()
                .filter(|name| scripts.contains_key(*name))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|scripts| !scripts.is_empty());
    let mut dependencies = BoundedDependencyCollector::new(max_packages);
    for (name, requirement) in package_json_dependencies(path, package, max_packages)? {
        let mut dependency = Dependency::declared(Ecosystem::Npm, &name, &requirement);
        if let Some((archive, commit)) = github_archive(&requirement) {
            dependency.resolved_version = Some(commit);
            dependency.source_url = Some(archive);
        }
        dependencies.push(dependency)?;
    }
    Ok((dependencies.into_dependencies(), install_scripts))
}

pub(super) struct EnrichResult {
    pub(super) contexts: HashMap<String, NpmLockContext>,
    pub(super) package_lock_context: Option<NpmLockContext>,
    pub(super) alternative_lock_context: Option<AlternativeLockContext>,
    /// True when this package directory selected any supported local npm lockfile.
    /// Callers must use this rather than `contexts.is_empty()`: a selected lockfile
    /// can validly produce no child contexts and must still suppress inheritance.
    pub(super) local_lockfile_selected: bool,
}

pub(super) enum AlternativeLockContext {
    Pnpm(PathBuf),
    Yarn(PathBuf),
}

pub(super) fn enrich(
    root: &ManifestRoot,
    dependencies: &mut [Dependency],
    lockfiles: &mut Vec<PathBuf>,
) -> Result<EnrichResult> {
    let directory = root.path();
    let mut selected = None;
    for name in ["npm-shrinkwrap.json", "package-lock.json"] {
        if root.is_file(Path::new(name))? {
            selected = Some(directory.join(name));
            break;
        }
    }
    let Some(path) = selected else {
        let alternative_lock_context = enrich_alternative_lock(root, dependencies, lockfiles)?;
        return Ok(EnrichResult {
            contexts: HashMap::new(),
            package_lock_context: None,
            local_lockfile_selected: alternative_lock_context.is_some(),
            alternative_lock_context,
        });
    };
    let context = NpmLockContext {
        lockfile: path.clone(),
        package_path: String::new(),
    };
    let contexts = enrich_from_context(&context, dependencies)?;
    lockfiles.push(path);
    Ok(EnrichResult {
        contexts,
        package_lock_context: Some(context),
        alternative_lock_context: None,
        local_lockfile_selected: true,
    })
}

pub(super) fn enrich_from_context(
    context: &NpmLockContext,
    dependencies: &mut [Dependency],
) -> Result<HashMap<String, NpmLockContext>> {
    package_lock::enrich(context, dependencies)
}

pub(super) fn workspace_members(
    root: &ManifestRoot,
    package: &Path,
    limits: &EngineLimits,
) -> Result<Vec<PathBuf>> {
    let value: JsonValue =
        serde_json::from_str(&read(package)?).map_err(|error| manifest_error(package, error))?;
    let package_json = value
        .as_object()
        .ok_or_else(|| manifest_error(package, "package.json root must be an object"))?;
    let Some(workspaces) = package_json.get("workspaces") else {
        return Ok(Vec::new());
    };
    let patterns = if let Some(patterns) = workspaces.as_array() {
        patterns
    } else {
        workspaces
            .as_object()
            .and_then(|workspaces| workspaces.get("packages"))
            .and_then(JsonValue::as_array)
            .ok_or_else(|| {
                manifest_error(
                    package,
                    "npm workspaces must be an array or an object with a packages array",
                )
            })?
    };

    let patterns = patterns
        .iter()
        .map(|pattern| {
            pattern
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| manifest_error(package, "npm workspace patterns must be strings"))
        })
        .collect::<Result<Vec<_>>>()?;
    let (includes, excludes) = workspace_globs(package, &patterns)?;
    let mut members = Vec::new();
    walk_workspace_beneath(
        root.path(),
        limits.max_package_depth,
        limits.max_source_files,
        &mut |entry, depth, kind| {
            if workspace_depth_exceeded(
                kind,
                depth,
                limits.max_package_depth,
                (includes.is_match(entry) && !excludes.is_match(entry))
                    || workspace_pattern_may_match_descendant(&patterns, entry),
            ) {
                return Err(crate::error::Error::LimitExceeded {
                    resource: "workspace depth".to_owned(),
                    limit: u64::try_from(limits.max_package_depth).unwrap_or(u64::MAX),
                });
            }
            if kind == RootedFileType::Symlink {
                if includes.is_match(entry) && !excludes.is_match(entry) {
                    return Err(manifest_error(
                        package,
                        format!(
                            "npm workspace member {} must not be a symbolic link",
                            entry.display()
                        ),
                    ));
                }
                return Ok(());
            }
            if kind != RootedFileType::File
                || entry.file_name().and_then(|name| name.to_str()) != Some("package.json")
            {
                return Ok(());
            }
            let member = entry
                .parent()
                .ok_or_else(|| manifest_error(package, "workspace member escaped its root"))?;
            if includes.is_match(member) && !excludes.is_match(member) {
                push_workspace_member_bounded(
                    &mut members,
                    member.to_path_buf(),
                    limits.max_packages,
                )?;
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
                "npm workspace patterns must remain within the workspace root",
            ));
        }
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
            "npm workspaces must contain at least one inclusion pattern",
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

/// Returns whether a lockfile reference can enrich a pinned GitHub archive declaration.
/// Non-GitHub declarations retain their existing lockfile behavior.
pub(super) fn matching_github_archive(
    dependency: &Dependency,
    reference: Option<&str>,
) -> Option<(String, String)> {
    let expected = github_archive(&dependency.requirement)?;
    let reference = reference?;
    (github_archive(reference).is_some_and(|archive| archive == expected)
        || reference.split('#').next() == Some(expected.0.as_str()))
    .then_some(expected)
}

pub(super) fn github_archive_matches(dependency: &Dependency, reference: Option<&str>) -> bool {
    github_archive(&dependency.requirement).is_none()
        || matching_github_archive(dependency, reference).is_some()
}

fn local_source_url(lockfile: &Path, reference: &str) -> Option<String> {
    local_source_url_from_directory(lockfile.parent()?, reference)
}

fn local_source_url_from_directory(directory: &Path, reference: &str) -> Option<String> {
    let path = ["file:", "link:", "portal:", "workspace:"]
        .into_iter()
        .find_map(|prefix| reference.strip_prefix(prefix))?;
    if path.is_empty() || matches!(path, "*" | "^" | "~") {
        return None;
    }

    let path = Path::new(path);
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        directory.join(path)
    };
    url::Url::from_file_path(path).ok().map(String::from)
}

pub(super) fn enrich_from_alternative_context(
    context: &AlternativeLockContext,
    member: &Path,
    dependencies: &mut [Dependency],
) -> Result<()> {
    let Some(components) = member
        .components()
        .try_fold(Vec::new(), |mut components, component| match component {
            Component::Normal(component) => {
                components.push(component.to_str()?);
                Some(components)
            }
            Component::CurDir => Some(components),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => None,
        })
    else {
        return Ok(());
    };
    let importer = if components.is_empty() {
        ".".to_owned()
    } else {
        components.join("/")
    };

    match context {
        AlternativeLockContext::Pnpm(path) => pnpm::enrich_importer(path, &importer, dependencies),
        AlternativeLockContext::Yarn(path) => {
            let Some(root) = path.parent() else {
                return Ok(());
            };
            yarn::enrich_from_directory(path, &root.join(member), dependencies)
        }
    }
}

fn enrich_alternative_lock(
    root: &ManifestRoot,
    dependencies: &mut [Dependency],
    lockfiles: &mut Vec<PathBuf>,
) -> Result<Option<AlternativeLockContext>> {
    let directory = root.path();
    let yarn_path = directory.join("yarn.lock");
    let pnpm_path = directory.join("pnpm-lock.yaml");
    let has_yarn = root.is_file(Path::new("yarn.lock"))?;
    let has_pnpm = root.is_file(Path::new("pnpm-lock.yaml"))?;
    if has_yarn && has_pnpm {
        return Err(manifest_error(
            &yarn_path,
            "both yarn.lock and pnpm-lock.yaml are present; lockfile selection is ambiguous",
        ));
    }
    if has_pnpm {
        pnpm::enrich(&pnpm_path, dependencies)?;
        lockfiles.push(pnpm_path.clone());
        Ok(Some(AlternativeLockContext::Pnpm(pnpm_path)))
    } else if has_yarn {
        yarn::enrich(&yarn_path, dependencies)?;
        lockfiles.push(yarn_path.clone());
        Ok(Some(AlternativeLockContext::Yarn(yarn_path)))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests;
