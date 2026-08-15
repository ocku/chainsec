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
    let declared = dependencies.clone();
    let mut resolutions = vec![Vec::new(); declared.len()];
    let mut merged_len = declared.len();
    for context in &contexts {
        // Each inherited lock represents an independent authorized resolution of the same
        // declarations. Never feed one context's resolved artifacts into another context.
        let mut contextual = declared.clone();
        context.enrich(&mut contextual, max_packages)?;
        for candidate in contextual {
            let declaration_index = declared
                .iter()
                .position(|declaration| {
                    declaration.ecosystem == candidate.ecosystem
                        && declaration.name == candidate.name
                        && declaration.requirement == candidate.requirement
                })
                .expect("Python lock enrichment preserves declaration identity");
            let declaration = &declared[declaration_index];
            if candidate == *declaration || candidate.resolved_version.is_none() {
                continue;
            }

            let alternatives = &mut resolutions[declaration_index];
            if alternatives.contains(&candidate) {
                continue;
            }
            if !alternatives.is_empty() {
                if merged_len >= max_packages {
                    return Err(crate::error::Error::LimitExceeded {
                        resource: "manifest dependencies".to_owned(),
                        limit: u64::try_from(max_packages).unwrap_or(u64::MAX),
                    });
                }
                merged_len += 1;
            }
            alternatives.push(candidate);
        }
        let path = context.path();
        if !lockfiles.iter().any(|lockfile| lockfile == path) {
            lockfiles.push(path.to_owned());
        }
    }

    if !contexts.is_empty() {
        let mut enriched = Vec::with_capacity(merged_len.min(max_packages));
        for (declaration, alternatives) in declared.into_iter().zip(resolutions) {
            if alternatives.is_empty() {
                extend_dependencies_bounded(&mut enriched, [declaration], max_packages)?;
            } else {
                extend_dependencies_bounded(&mut enriched, alternatives, max_packages)?;
            }
        }
        *dependencies = enriched;
    }
    Ok(contexts.into_iter().collect())
}

#[cfg(test)]
mod tests;
