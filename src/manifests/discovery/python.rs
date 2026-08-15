use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use super::super::shared::{ManifestRoot, extend_dependencies_bounded};
use super::super::{InstallScriptWarning, PythonLockContext, python as python_manifest};
use crate::{
    error::Result,
    model::{Dependency, EngineLimits, Language},
};

pub(super) fn discover_python(
    manifest_root: &ManifestRoot,
    inherited_contexts: &[PythonLockContext],
    dependencies: &mut Vec<Dependency>,
    lockfiles: &mut Vec<PathBuf>,
    install_scripts: &mut Vec<InstallScriptWarning>,
    contexts: &mut BTreeSet<PythonLockContext>,
    limits: &EngineLimits,
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
    let pipfile = root.join("Pipfile");
    let has_pyproject = manifest_root.is_file(Path::new("pyproject.toml"))?;
    let has_pipfile = manifest_root.is_file(Path::new("Pipfile"))?;
    if !has_pyproject && !has_pipfile {
        return Ok(());
    }
    for lockfile in ["poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock"] {
        manifest_root.is_file(Path::new(lockfile))?;
    }
    let mut python_dependencies = Vec::new();
    if has_pyproject {
        extend_dependencies_bounded(
            &mut python_dependencies,
            python_manifest::parse_with_limit(&pyproject, limits.max_packages)?,
            limits.max_packages,
        )?;
    }
    if has_pipfile {
        extend_dependencies_bounded(
            &mut python_dependencies,
            python_manifest::parse_pipfile_with_limit(&pipfile, limits.max_packages)?,
            limits.max_packages,
        )?;
    }
    match python_manifest::enrich(
        manifest_root,
        &mut python_dependencies,
        lockfiles,
        inherited_contexts,
        limits.max_packages,
    ) {
        Ok(python_contexts) => *contexts = python_contexts,
        Err(error) => {
            // Keep declarations visible so an enrichment failure cannot suppress them.
            extend_dependencies_bounded(dependencies, python_dependencies, limits.max_packages)?;
            return Err(error);
        }
    }
    extend_dependencies_bounded(dependencies, python_dependencies, limits.max_packages)
}
