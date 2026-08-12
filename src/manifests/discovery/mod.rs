use std::{
    collections::{BTreeSet, HashMap},
    path::{Path, PathBuf},
};

use super::{
    Discovery, DiscoveryOutcome, InstallScriptWarning, NpmLockContext, PythonLockContext, deno,
    npm, python,
};
use crate::{
    error::{Error, Result},
    model::{Dependency, Language},
};

use super::shared::{ManifestRoot, with_manifest_roots};

pub fn discover(root: &Path) -> Result<Discovery> {
    let outcome = discover_with_contexts(root, &[], &[]);
    if let Some(error) = outcome.errors.into_iter().next() {
        return Err(error);
    }
    Ok(outcome.discovery)
}

pub(crate) fn discover_with_contexts(
    root: &Path,
    inherited_npm_contexts: &[NpmLockContext],
    inherited_python_contexts: &[PythonLockContext],
) -> DiscoveryOutcome {
    let dependencies = Vec::new();
    let lockfiles = Vec::new();
    let manifest_root = match ManifestRoot::open(root) {
        Ok(root) => root,
        Err(error) => {
            return empty_outcome(dependencies, lockfiles, error);
        }
    };
    let mut roots = vec![manifest_root];
    if let Err(error) = add_inherited_roots(
        &mut roots,
        inherited_npm_contexts,
        inherited_python_contexts,
    ) {
        return empty_outcome(dependencies, lockfiles, error);
    }
    let rooted = with_manifest_roots(&roots, || {
        discover_rooted(&roots[0], inherited_npm_contexts, inherited_python_contexts)
    });
    match rooted {
        Ok(outcome) => outcome,
        Err(error) => empty_outcome(dependencies, lockfiles, error),
    }
}

fn add_inherited_roots(
    roots: &mut Vec<ManifestRoot>,
    npm_contexts: &[NpmLockContext],
    python_contexts: &[PythonLockContext],
) -> Result<()> {
    let npm_paths = npm_contexts
        .iter()
        .map(|context| context.lockfile.as_path());
    let python_paths = python_contexts.iter().map(|context| match context {
        PythonLockContext::Poetry(path)
        | PythonLockContext::Pipfile(path)
        | PythonLockContext::Uv(path)
        | PythonLockContext::Pdm(path) => path.as_path(),
    });
    for path in npm_paths.chain(python_paths) {
        let Some(parent) = path.parent() else {
            return Err(super::shared::manifest_error(
                path,
                "inherited lockfile has no containing directory",
            ));
        };
        let root = ManifestRoot::open(parent)?;
        if !roots.iter().any(|existing| existing.path() == root.path()) {
            roots.push(root);
        }
    }
    Ok(())
}

fn empty_outcome(
    dependencies: Vec<Dependency>,
    lockfiles: Vec<PathBuf>,
    error: Error,
) -> DiscoveryOutcome {
    DiscoveryOutcome {
        discovery: Discovery {
            dependencies,
            lockfiles,
            install_scripts: Vec::new(),
            npm_contexts: HashMap::new(),
        },
        python_contexts: Default::default(),
        errors: vec![error],
    }
}

fn discover_rooted(
    manifest_root: &ManifestRoot,
    inherited_npm_contexts: &[NpmLockContext],
    inherited_python_contexts: &[PythonLockContext],
) -> DiscoveryOutcome {
    let mut dependencies = Vec::new();
    let mut lockfiles = Vec::new();
    let mut install_scripts = Vec::new();
    let mut python_contexts = BTreeSet::new();
    let mut errors = Vec::new();

    if let Err(error) = discover_python(
        manifest_root,
        inherited_python_contexts,
        &mut dependencies,
        &mut lockfiles,
        &mut install_scripts,
        &mut python_contexts,
    ) {
        errors.push(error);
    }
    let npm_contexts = match discover_npm(
        manifest_root,
        inherited_npm_contexts,
        &mut dependencies,
        &mut lockfiles,
        &mut install_scripts,
    ) {
        Ok(contexts) => contexts,
        Err(error) => {
            errors.push(error);
            HashMap::new()
        }
    };
    if let Err(error) = discover_deno(manifest_root, &mut dependencies, &mut lockfiles) {
        errors.push(error);
    }

    normalize_discovery(&mut dependencies, &mut lockfiles);

    DiscoveryOutcome {
        discovery: Discovery {
            dependencies,
            lockfiles,
            install_scripts,
            npm_contexts,
        },
        python_contexts,
        errors,
    }
}

fn normalize_discovery(dependencies: &mut Vec<Dependency>, lockfiles: &mut Vec<PathBuf>) {
    dependencies.sort_by(|a, b| {
        (
            a.ecosystem.to_string(),
            &a.name,
            &a.requirement,
            &a.resolved_version,
            &a.source_url,
            &a.integrity,
            &a.lockfile,
            a.deno_lockfile_snapshot
                .as_ref()
                .map(crate::model::DenoLockfileSnapshot::identity),
            a.registry_integrity_required,
        )
            .cmp(&(
                b.ecosystem.to_string(),
                &b.name,
                &b.requirement,
                &b.resolved_version,
                &b.source_url,
                &b.integrity,
                &b.lockfile,
                b.deno_lockfile_snapshot
                    .as_ref()
                    .map(crate::model::DenoLockfileSnapshot::identity),
                b.registry_integrity_required,
            ))
    });
    dependencies.dedup();
    lockfiles.sort();
    lockfiles.dedup();
}

fn discover_python(
    manifest_root: &ManifestRoot,
    inherited_contexts: &[PythonLockContext],
    dependencies: &mut Vec<Dependency>,
    lockfiles: &mut Vec<PathBuf>,
    install_scripts: &mut Vec<InstallScriptWarning>,
    contexts: &mut BTreeSet<PythonLockContext>,
) -> Result<()> {
    let root = manifest_root.path();
    let setup_py = root.join("setup.py");
    if manifest_root.is_file(Path::new("setup.py"))? {
        install_scripts.push(InstallScriptWarning {
            language: Language::Python,
            manifest: setup_py,
            scripts: vec!["setup.py".to_owned()],
        });
    }

    let pyproject = root.join("pyproject.toml");
    if !manifest_root.is_file(Path::new("pyproject.toml"))? {
        return Ok(());
    }
    for lockfile in ["poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock"] {
        manifest_root.is_file(Path::new(lockfile))?;
    }
    let mut python_dependencies = python::parse(&pyproject)?;
    match python::enrich(
        manifest_root,
        &mut python_dependencies,
        lockfiles,
        inherited_contexts,
    ) {
        Ok(python_contexts) => *contexts = python_contexts,
        Err(error) => {
            // Keep declarations visible so an enrichment failure cannot suppress them.
            dependencies.extend(python_dependencies);
            return Err(error);
        }
    }
    dependencies.extend(python_dependencies);
    Ok(())
}

fn discover_npm(
    manifest_root: &ManifestRoot,
    inherited_contexts: &[NpmLockContext],
    dependencies: &mut Vec<Dependency>,
    lockfiles: &mut Vec<PathBuf>,
    install_scripts: &mut Vec<InstallScriptWarning>,
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
    let (npm_dependencies, lifecycle_scripts) = npm::parse(&package)?;
    if let Some(scripts) = lifecycle_scripts {
        install_scripts.push(InstallScriptWarning {
            language: Language::JavaScript,
            manifest: package.clone(),
            scripts,
        });
    }

    let mut local_dependencies = npm_dependencies.clone();
    let (local_contexts, package_lock_context, selected_local_lock) =
        match enrich_npm_locally(manifest_root, &mut local_dependencies, lockfiles) {
            Ok(result) => result,
            Err(error) => {
                // Keep declarations visible so an enrichment failure cannot suppress them.
                dependencies.extend(local_dependencies);
                return Err(error);
            }
        };
    let mut contexts = context_sets(local_contexts);
    let mut workspace_dependencies = Vec::new();
    for member in npm::workspace_members(manifest_root, &package)? {
        let member_package = root.join(&member).join("package.json");
        let (mut member_dependencies, lifecycle_scripts) = npm::parse(&member_package)?;
        if let Some(scripts) = lifecycle_scripts {
            install_scripts.push(InstallScriptWarning {
                language: Language::JavaScript,
                manifest: member_package,
                scripts,
            });
        }
        workspace_dependencies.push((member.clone(), member_dependencies.clone()));
        if let Some(context) = package_lock_context.as_ref() {
            let mut context = context.clone();
            context.package_path = npm_importer_path(&context.package_path, &member);
            let member_contexts = npm::enrich_from_context(&context, &mut member_dependencies)?;
            for (dependency, child_context) in member_contexts {
                contexts
                    .entry(dependency)
                    .or_default()
                    .insert(child_context);
            }
        }
        local_dependencies.extend(member_dependencies);
    }
    if selected_local_lock || inherited_contexts.is_empty() {
        dependencies.extend(local_dependencies);
        return Ok(contexts);
    }

    let mut inherited_contexts_by_dependency = HashMap::<String, BTreeSet<NpmLockContext>>::new();
    for context in inherited_contexts {
        let mut contextual_dependencies = npm_dependencies.clone();
        let child_contexts = npm::enrich_from_context(context, &mut contextual_dependencies)?;
        if contextual_dependencies
            .iter()
            .any(|dependency| dependency.lockfile.is_some())
        {
            lockfiles.push(context.lockfile.clone());
        }
        dependencies.extend(contextual_dependencies);
        for (member, member_dependencies) in &workspace_dependencies {
            let mut contextual_dependencies = member_dependencies.clone();
            let mut member_context = context.clone();
            member_context.package_path = npm_importer_path(&member_context.package_path, member);
            let member_child_contexts =
                npm::enrich_from_context(&member_context, &mut contextual_dependencies)?;
            if contextual_dependencies
                .iter()
                .any(|dependency| dependency.lockfile.is_some())
            {
                lockfiles.push(context.lockfile.clone());
            }
            dependencies.extend(contextual_dependencies);
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

fn enrich_npm_locally(
    root: &ManifestRoot,
    dependencies: &mut [Dependency],
    lockfiles: &mut Vec<PathBuf>,
) -> Result<(
    HashMap<String, NpmLockContext>,
    Option<NpmLockContext>,
    bool,
)> {
    let result = npm::enrich(root, dependencies, lockfiles)?;
    Ok((
        result.contexts,
        result.package_lock_context,
        result.local_lockfile_selected,
    ))
}

fn discover_deno(
    root: &ManifestRoot,
    dependencies: &mut Vec<Dependency>,
    lockfiles: &mut Vec<PathBuf>,
) -> Result<()> {
    let directory = root.path();
    let Some(manifest) = deno::select_manifest(root)? else {
        return Ok(());
    };

    let parsed = deno::parse(directory, &manifest)?;
    let mut imports = parsed.dependencies;
    if let Err(error) = deno::enrich(directory, &parsed.lockfile, &mut imports, lockfiles) {
        // Keep declarations visible so an enrichment failure cannot suppress them.
        dependencies.extend(imports);
        return Err(error);
    }
    dependencies.extend(imports);
    Ok(())
}

#[cfg(test)]
mod tests;
