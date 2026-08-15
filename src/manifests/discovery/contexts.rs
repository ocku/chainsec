use std::path::Path;

use super::super::shared::{ManifestRoot, manifest_error};
use super::super::{NpmLockContext, PythonLockContext};
use crate::error::Result;

// Declaration contexts use the existing internal npm context channel, but traversal removes
// them before passing lock contexts to a fetched dependency.
const NPM_DECLARATION_CONTEXT: &str = "\0chainsec:npm-declaration";

impl NpmLockContext {
    pub(super) fn declaration(manifest: &Path) -> Self {
        Self {
            lockfile: manifest.to_owned(),
            package_path: NPM_DECLARATION_CONTEXT.to_owned(),
        }
    }

    pub(crate) fn declaration_directory(&self) -> Option<&Path> {
        (self.package_path == NPM_DECLARATION_CONTEXT
            && self
                .lockfile
                .file_name()
                .is_some_and(|name| name == "package.json"))
        .then(|| self.lockfile.parent())
        .flatten()
    }
}

pub(super) fn add_inherited_roots(
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
            return Err(manifest_error(
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
