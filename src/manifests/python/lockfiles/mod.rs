use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use crate::{error::Result, manifests::shared::ManifestRoot, model::Dependency};

mod artifact;
mod common;
mod pipfile;
mod toml;

pub(super) use common::package_string;
use toml::{enrich_pdm, enrich_poetry, enrich_uv};

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

    fn enrich(&self, dependencies: &mut Vec<Dependency>) -> Result<()> {
        match self {
            Self::Poetry(path) => enrich_poetry(path, dependencies),
            Self::Pipfile(path) => pipfile::enrich(path, dependencies),
            Self::Uv(path) => enrich_uv(path, dependencies),
            Self::Pdm(path) => enrich_pdm(path, dependencies),
        }
    }
}

pub(in crate::manifests) fn enrich(
    root: &ManifestRoot,
    dependencies: &mut Vec<Dependency>,
    lockfiles: &mut Vec<PathBuf>,
    inherited_contexts: &[PythonLockContext],
) -> Result<BTreeSet<PythonLockContext>> {
    let contexts = match PythonLockContext::find(root)? {
        Some(context) => vec![context],
        None => inherited_contexts.to_vec(),
    };
    for context in &contexts {
        context.enrich(dependencies)?;
        let path = context.path();
        if !lockfiles.iter().any(|lockfile| lockfile == path) {
            lockfiles.push(path.to_owned());
        }
    }
    Ok(contexts.into_iter().collect())
}

#[cfg(test)]
mod tests;
