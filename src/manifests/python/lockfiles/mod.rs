use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use crate::{
    error::Result,
    manifests::shared::{ManifestRoot, extend_dependencies_bounded},
    model::Dependency,
};

mod artifact;
mod common;
mod pipfile;
mod toml;

pub(super) use common::package_string;
use toml::{enrich_pdm_bounded, enrich_poetry_bounded, enrich_uv_bounded};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum PythonLockContext {
    Poetry(PathBuf),
    Pipfile(PathBuf),
    Uv(PathBuf),
    Pdm(PathBuf),
}

impl PythonLockContext {
    fn find(root: &ManifestRoot) -> Result<Option<Self>> {
        let directory = root.path();
        let mut contexts = Vec::new();
        for (name, context) in [
            ("poetry.lock", Self::Poetry(directory.join("poetry.lock"))),
            (
                "Pipfile.lock",
                Self::Pipfile(directory.join("Pipfile.lock")),
            ),
            ("uv.lock", Self::Uv(directory.join("uv.lock"))),
            ("pdm.lock", Self::Pdm(directory.join("pdm.lock"))),
        ] {
            if root.is_file(Path::new(name))? {
                contexts.push(context);
            }
        }
        match contexts.as_slice() {
            [] => Ok(None),
            [context] => Ok(Some(context.clone())),
            _ => Err(crate::manifests::shared::manifest_error(
                directory,
                "multiple Python lockfiles are present; lockfile selection is ambiguous",
            )),
        }
    }

    fn path(&self) -> &Path {
        match self {
            Self::Poetry(path) | Self::Pipfile(path) | Self::Uv(path) | Self::Pdm(path) => path,
        }
    }

    fn enrich(&self, dependencies: &mut Vec<Dependency>, max_packages: usize) -> Result<()> {
        match self {
            Self::Poetry(path) => enrich_poetry_bounded(path, dependencies, max_packages),
            Self::Pipfile(path) => pipfile::enrich_bounded(path, dependencies, max_packages),
            Self::Uv(path) => enrich_uv_bounded(path, dependencies, max_packages),
            Self::Pdm(path) => enrich_pdm_bounded(path, dependencies, max_packages),
        }
    }
}

pub(in crate::manifests) fn enrich(
    root: &ManifestRoot,
    dependencies: &mut Vec<Dependency>,
    lockfiles: &mut Vec<PathBuf>,
    inherited_contexts: &[PythonLockContext],
    max_packages: usize,
) -> Result<BTreeSet<PythonLockContext>> {
    let contexts = match PythonLockContext::find(root)? {
        Some(context) => vec![context],
        None => inherited_contexts.to_vec(),
    };
    for context in &contexts {
        // Enrichment is fallible and may expand one declaration into multiple authorized
        // artifacts. Work on a copy so malformed lock data cannot erase declarations, then apply
        // the package budget before another inherited context can amplify the result again.
        let mut enriched = dependencies.clone();
        context.enrich(&mut enriched, max_packages)?;
        let mut bounded = Vec::new();
        extend_dependencies_bounded(&mut bounded, enriched, max_packages)?;
        *dependencies = bounded;
        let path = context.path();
        if !lockfiles.iter().any(|lockfile| lockfile == path) {
            lockfiles.push(path.to_owned());
        }
    }
    Ok(contexts.into_iter().collect())
}

#[cfg(test)]
mod tests;
