use std::{
    collections::{BTreeSet, HashMap},
    path::{Path, PathBuf},
};

use super::super::shared::{ManifestRoot, with_manifest_roots_and_limit};
use super::super::{Discovery, DiscoveryOutcome, NpmLockContext, PythonLockContext};
use super::{
    contexts::add_inherited_roots, deno::discover_deno, npm::discover_npm, python::discover_python,
};
use crate::{
    error::Error,
    model::{Dependency, EngineLimits},
};

pub(super) fn discover_with_contexts(
    root: &Path,
    inherited_npm_contexts: &[NpmLockContext],
    inherited_python_contexts: &[PythonLockContext],
) -> DiscoveryOutcome {
    discover_with_contexts_and_limits(
        root,
        inherited_npm_contexts,
        inherited_python_contexts,
        &EngineLimits::default(),
    )
}

pub(super) fn discover_with_contexts_and_limits(
    root: &Path,
    inherited_npm_contexts: &[NpmLockContext],
    inherited_python_contexts: &[PythonLockContext],
    limits: &EngineLimits,
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
    let rooted = with_manifest_roots_and_limit(&roots, limits.max_manifest_file_size, || {
        discover_rooted(
            &roots[0],
            inherited_npm_contexts,
            inherited_python_contexts,
            limits,
        )
    });
    match rooted {
        Ok(outcome) => outcome,
        Err(error) => empty_outcome(dependencies, lockfiles, error),
    }
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
    limits: &EngineLimits,
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
        limits,
    ) {
        errors.push(error);
    }
    let mut npm_contexts = match discover_npm(
        manifest_root,
        inherited_npm_contexts,
        &mut dependencies,
        &mut lockfiles,
        &mut install_scripts,
        limits,
    ) {
        Ok(contexts) => contexts,
        Err(error) => {
            errors.push(error);
            HashMap::new()
        }
    };
    if let Err(error) = discover_deno(
        manifest_root,
        &mut dependencies,
        &mut lockfiles,
        &mut npm_contexts,
        limits,
    ) {
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

pub(super) fn normalize_discovery(
    dependencies: &mut Vec<Dependency>,
    lockfiles: &mut Vec<PathBuf>,
) {
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
