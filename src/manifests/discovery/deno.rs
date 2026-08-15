use std::{
    collections::{BTreeSet, HashMap},
    path::PathBuf,
};

use super::super::shared::extend_dependencies_bounded;
use super::super::{NpmLockContext, deno as deno_manifest, shared::ManifestRoot};
use crate::{
    error::Result,
    model::{Dependency, EngineLimits},
};

pub(super) fn discover_deno(
    root: &ManifestRoot,
    dependencies: &mut Vec<Dependency>,
    lockfiles: &mut Vec<PathBuf>,
    npm_contexts: &mut HashMap<String, BTreeSet<NpmLockContext>>,
    limits: &EngineLimits,
) -> Result<()> {
    let directory = root.path();
    let Some(manifest) = deno_manifest::select_manifest(root)? else {
        return Ok(());
    };

    let parsed = deno_manifest::parse_with_limits(directory, &manifest, limits)?;
    for (dependency, manifest) in parsed.local_declarations {
        npm_contexts
            .entry(dependency)
            .or_default()
            .insert(NpmLockContext::declaration(&manifest));
    }

    let mut manifest_dependencies = parsed.dependencies;
    if let Err(error) = deno_manifest::enrich(
        directory,
        &parsed.lockfile,
        &mut manifest_dependencies,
        lockfiles,
        limits,
    ) {
        // Keep declarations visible so an enrichment failure cannot suppress them.
        extend_dependencies_bounded(dependencies, manifest_dependencies, limits.max_packages)?;
        return Err(error);
    }
    extend_dependencies_bounded(dependencies, manifest_dependencies, limits.max_packages)
}
