use std::{
    collections::{BTreeSet, HashMap},
    path::{Path, PathBuf},
};

use super::super::shared::{ManifestRoot, extend_dependencies_bounded};
use super::super::{InstallScriptWarning, NpmLockContext, npm as npm_manifest};
use crate::{
    error::Result,
    model::{Dependency, EngineLimits, Language},
};

pub(super) fn discover_npm(
    manifest_root: &ManifestRoot,
    inherited_contexts: &[NpmLockContext],
    dependencies: &mut Vec<Dependency>,
    lockfiles: &mut Vec<PathBuf>,
    install_scripts: &mut Vec<InstallScriptWarning>,
    limits: &EngineLimits,
) -> Result<HashMap<String, BTreeSet<NpmLockContext>>> {
    let root = manifest_root.path();
    let package = root.join("package.json");
    if !manifest_root.is_file(Path::new("package.json"))? {
        return Ok(HashMap::new());
    }

    for lockfile in [
        "npm-shrinkwrap.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
    ] {
        manifest_root.is_file(Path::new(lockfile))?;
    }

    let npm_dependencies = parse_manifest(&package, install_scripts, limits)?;
    let mut local_dependencies = npm_dependencies.clone();
    let npm_manifest::EnrichResult {
        contexts: local_contexts,
        package_lock_context,
        alternative_lock_context,
        local_lockfile_selected: selected_local_lock,
    } = enrich_local(
        manifest_root,
        &mut local_dependencies,
        lockfiles,
        dependencies,
        limits,
    )?;
    let mut contexts = context_sets(local_contexts);
    record_npm_declarations(&mut contexts, &package, &local_dependencies);

    let workspace_dependencies = discover_workspace_members(
        manifest_root,
        root,
        &package,
        &mut local_dependencies,
        &mut contexts,
        &package_lock_context,
        &alternative_lock_context,
        dependencies,
        install_scripts,
        limits,
    )?;

    if selected_local_lock || inherited_contexts.is_empty() {
        extend_dependencies_bounded(dependencies, local_dependencies, limits.max_packages)?;
        return Ok(contexts);
    }

    process_inherited_contexts(
        inherited_contexts,
        &npm_dependencies,
        &workspace_dependencies,
        root,
        &package,
        dependencies,
        lockfiles,
        limits,
    )
}

/// Parse a package.json, recording any lifecycle install scripts it declares.
fn parse_manifest(
    manifest: &Path,
    install_scripts: &mut Vec<InstallScriptWarning>,
    limits: &EngineLimits,
) -> Result<Vec<Dependency>> {
    let (dependencies, lifecycle_scripts) =
        npm_manifest::parse_with_limit(manifest, limits.max_packages)?;
    if let Some(scripts) = lifecycle_scripts {
        install_scripts.push(InstallScriptWarning {
            language: Language::JavaScript,
            manifest: manifest.to_owned(),
            scripts,
        });
    }
    Ok(dependencies)
}

/// Enrich the local manifest against its own lockfile, keeping declarations visible if it fails.
fn enrich_local(
    manifest_root: &ManifestRoot,
    local_dependencies: &mut Vec<Dependency>,
    lockfiles: &mut Vec<PathBuf>,
    dependencies: &mut Vec<Dependency>,
    limits: &EngineLimits,
) -> Result<npm_manifest::EnrichResult> {
    match npm_manifest::enrich(manifest_root, local_dependencies, lockfiles) {
        Ok(result) => Ok(result),
        Err(error) => {
            // Keep declarations visible so an enrichment failure cannot suppress them.
            extend_dependencies_bounded(
                dependencies,
                std::mem::take(local_dependencies),
                limits.max_packages,
            )?;
            Err(error)
        }
    }
}

/// Parse and enrich each workspace member, accumulating its dependencies and child contexts.
#[allow(clippy::too_many_arguments)]
fn discover_workspace_members(
    manifest_root: &ManifestRoot,
    root: &Path,
    package: &Path,
    local_dependencies: &mut Vec<Dependency>,
    contexts: &mut HashMap<String, BTreeSet<NpmLockContext>>,
    package_lock_context: &Option<NpmLockContext>,
    alternative_lock_context: &Option<npm_manifest::AlternativeLockContext>,
    dependencies: &mut Vec<Dependency>,
    install_scripts: &mut Vec<InstallScriptWarning>,
    limits: &EngineLimits,
) -> Result<Vec<(PathBuf, Vec<Dependency>)>> {
    let mut workspace_dependencies = Vec::new();
    for member in npm_manifest::workspace_members(manifest_root, package, limits)? {
        let member_package = root.join(&member).join("package.json");
        let mut member_dependencies = parse_manifest(&member_package, install_scripts, limits)?;
        workspace_dependencies.push((member.clone(), member_dependencies.clone()));
        if let Err(error) = enrich_member(
            &member,
            &mut member_dependencies,
            contexts,
            package_lock_context,
            alternative_lock_context,
        ) {
            // Keep declarations visible so a member enrichment failure cannot suppress them.
            extend_dependencies_bounded(
                dependencies,
                std::mem::take(local_dependencies),
                limits.max_packages,
            )?;
            return Err(error);
        }
        record_npm_declarations(contexts, &member_package, &member_dependencies);
        extend_dependencies_bounded(local_dependencies, member_dependencies, limits.max_packages)?;
    }
    Ok(workspace_dependencies)
}

/// Enrich a single workspace member against the root's selected lockfile.
fn enrich_member(
    member: &Path,
    member_dependencies: &mut [Dependency],
    contexts: &mut HashMap<String, BTreeSet<NpmLockContext>>,
    package_lock_context: &Option<NpmLockContext>,
    alternative_lock_context: &Option<npm_manifest::AlternativeLockContext>,
) -> Result<()> {
    if let Some(context) = package_lock_context.as_ref() {
        let mut context = context.clone();
        context.package_path = npm_importer_path(&context.package_path, member);
        let member_contexts = npm_manifest::enrich_from_context(&context, member_dependencies)?;
        for (dependency, child_context) in member_contexts {
            contexts
                .entry(dependency)
                .or_default()
                .insert(child_context);
        }
    } else if let Some(context) = alternative_lock_context.as_ref() {
        npm_manifest::enrich_from_alternative_context(context, member, member_dependencies)?;
    }
    Ok(())
}

/// Enrich the root and every workspace member against each inherited lockfile context.
#[allow(clippy::too_many_arguments)]
fn process_inherited_contexts(
    inherited_contexts: &[NpmLockContext],
    npm_dependencies: &[Dependency],
    workspace_dependencies: &[(PathBuf, Vec<Dependency>)],
    root: &Path,
    package: &Path,
    dependencies: &mut Vec<Dependency>,
    lockfiles: &mut Vec<PathBuf>,
    limits: &EngineLimits,
) -> Result<HashMap<String, BTreeSet<NpmLockContext>>> {
    let mut inherited_contexts_by_dependency = HashMap::<String, BTreeSet<NpmLockContext>>::new();
    for context in inherited_contexts {
        let mut contextual_dependencies = npm_dependencies.to_vec();
        let child_contexts =
            npm_manifest::enrich_from_context(context, &mut contextual_dependencies)?;
        if has_lockfile(&contextual_dependencies) {
            lockfiles.push(context.lockfile.clone());
        }
        record_npm_declarations(
            &mut inherited_contexts_by_dependency,
            package,
            &contextual_dependencies,
        );
        extend_dependencies_bounded(dependencies, contextual_dependencies, limits.max_packages)?;
        for (member, member_dependencies) in workspace_dependencies {
            let mut contextual_dependencies = member_dependencies.clone();
            let mut member_context = context.clone();
            member_context.package_path = npm_importer_path(&member_context.package_path, member);
            let member_child_contexts =
                npm_manifest::enrich_from_context(&member_context, &mut contextual_dependencies)?;
            if has_lockfile(&contextual_dependencies) {
                lockfiles.push(context.lockfile.clone());
            }
            record_npm_declarations(
                &mut inherited_contexts_by_dependency,
                &root.join(member).join("package.json"),
                &contextual_dependencies,
            );
            extend_dependencies_bounded(
                dependencies,
                contextual_dependencies,
                limits.max_packages,
            )?;
            for (dependency, child_context) in member_child_contexts {
                inherited_contexts_by_dependency
                    .entry(dependency)
                    .or_default()
                    .insert(child_context);
            }
        }
        for (dependency, child_context) in child_contexts {
            inherited_contexts_by_dependency
                .entry(dependency)
                .or_default()
                .insert(child_context);
        }
    }
    Ok(inherited_contexts_by_dependency)
}

fn has_lockfile(dependencies: &[Dependency]) -> bool {
    dependencies
        .iter()
        .any(|dependency| dependency.lockfile.is_some())
}

// Keep the npm implementation's return shape isolated here so pending npm enrichment API
// changes only require adapting this bridge.
fn npm_importer_path(base: &str, member: &Path) -> String {
    let member = member
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(component) => component.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/");
    if base.is_empty() {
        member
    } else if member.is_empty() {
        base.to_owned()
    } else {
        format!("{base}/{member}")
    }
}

fn context_sets(
    contexts: HashMap<String, NpmLockContext>,
) -> HashMap<String, BTreeSet<NpmLockContext>> {
    contexts
        .into_iter()
        .map(|(dependency, context)| (dependency, BTreeSet::from([context])))
        .collect()
}

fn record_npm_declarations(
    contexts: &mut HashMap<String, BTreeSet<NpmLockContext>>,
    manifest: &Path,
    dependencies: &[Dependency],
) {
    let declaration = NpmLockContext::declaration(manifest);
    for dependency in dependencies
        .iter()
        .filter(|dependency| dependency.is_local())
    {
        contexts
            .entry(dependency.npm_declaration_key())
            .or_default()
            .insert(declaration.clone());
    }
}
