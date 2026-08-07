use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use crate::{
    error::Result,
    model::{Dependency, Language},
};

mod deno;
mod npm;
mod python;
mod shared;

#[cfg(test)]
use deno::strip_jsonc;
pub(crate) use python::PythonLockContext;

#[derive(Debug, Clone)]
pub(crate) struct NpmLockContext {
    lockfile: PathBuf,
    package_path: String,
}

#[derive(Debug, Clone)]
pub struct InstallScriptWarning {
    pub language: Language,
    pub manifest: PathBuf,
    pub scripts: Vec<String>,
}

#[derive(Debug)]
pub struct Discovery {
    pub dependencies: Vec<Dependency>,
    pub lockfiles: Vec<PathBuf>,
    pub install_scripts: Vec<InstallScriptWarning>,
    pub(crate) npm_contexts: HashMap<String, NpmLockContext>,
}

pub fn discover(root: &Path) -> Result<Discovery> {
    Ok(discover_with_contexts(root, None, None)?.0)
}

pub(crate) fn discover_with_contexts(
    root: &Path,
    inherited_npm_context: Option<&NpmLockContext>,
    inherited_python_context: Option<&PythonLockContext>,
) -> Result<(Discovery, Option<PythonLockContext>)> {
    let mut dependencies = Vec::new();
    let mut lockfiles = Vec::new();

    let mut install_scripts = Vec::new();
    let mut python_context = None;

    discover_python(
        root,
        inherited_python_context,
        &mut dependencies,
        &mut lockfiles,
        &mut install_scripts,
        &mut python_context,
    )?;
    let npm_contexts = discover_npm(
        root,
        inherited_npm_context,
        &mut dependencies,
        &mut lockfiles,
        &mut install_scripts,
    )?;
    discover_deno(root, &mut dependencies, &mut lockfiles)?;

    dependencies.sort_by_cached_key(Dependency::id);
    dependencies.dedup_by(|a, b| {
        a.ecosystem == b.ecosystem && a.name == b.name && a.requirement == b.requirement
    });
    Ok((
        Discovery {
            dependencies,
            lockfiles,
            install_scripts,
            npm_contexts,
        },
        python_context,
    ))
}

fn discover_python(
    root: &Path,
    inherited_context: Option<&PythonLockContext>,
    dependencies: &mut Vec<Dependency>,
    lockfiles: &mut Vec<PathBuf>,
    install_scripts: &mut Vec<InstallScriptWarning>,
    context: &mut Option<PythonLockContext>,
) -> Result<()> {
    let setup_py = root.join("setup.py");
    if setup_py.is_file() {
        install_scripts.push(InstallScriptWarning {
            language: Language::Python,
            manifest: setup_py,
            scripts: vec!["setup.py".to_owned()],
        });
    }

    let pyproject = root.join("pyproject.toml");
    if !pyproject.is_file() {
        return Ok(());
    }
    let mut python_dependencies = python::parse(&pyproject)?;
    *context = python::enrich(root, &mut python_dependencies, lockfiles, inherited_context)?;
    dependencies.extend(python_dependencies);
    Ok(())
}

fn discover_npm(
    root: &Path,
    inherited_context: Option<&NpmLockContext>,
    dependencies: &mut Vec<Dependency>,
    lockfiles: &mut Vec<PathBuf>,
    install_scripts: &mut Vec<InstallScriptWarning>,
) -> Result<HashMap<String, NpmLockContext>> {
    let package = root.join("package.json");
    if !package.is_file() {
        return Ok(HashMap::new());
    }

    let mut npm_dependencies = npm::parse(&package)?;
    if let Some(scripts) = npm::install_scripts(&package)? {
        install_scripts.push(InstallScriptWarning {
            language: Language::JavaScript,
            manifest: package.clone(),
            scripts,
        });
    }

    let mut contexts = npm::enrich(root, &mut npm_dependencies, lockfiles)?;
    if contexts.is_empty()
        && let Some(context) = inherited_context
    {
        contexts = npm::enrich_from_context(context, &mut npm_dependencies)?;
        if npm_dependencies
            .iter()
            .any(|dependency| dependency.lockfile.is_some())
        {
            lockfiles.push(context.lockfile.clone());
        }
    }
    dependencies.extend(npm_dependencies);
    Ok(contexts)
}

fn discover_deno(
    root: &Path,
    dependencies: &mut Vec<Dependency>,
    lockfiles: &mut Vec<PathBuf>,
) -> Result<()> {
    let Some(manifest) = ["deno.json", "deno.jsonc"]
        .into_iter()
        .map(|name| root.join(name))
        .find(|path| path.is_file())
    else {
        return Ok(());
    };

    let mut imports = deno::parse(&manifest)?;
    deno::enrich(root, &mut imports, lockfiles)?;
    dependencies.extend(imports);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonc_preserves_comment_markers_in_strings() {
        let clean = strip_jsonc("{\"url\":\"https://example.test/a//b\" // comment\n}").unwrap();
        let value: serde_json::Value = serde_json::from_str(&clean).unwrap();
        assert_eq!(value["url"], "https://example.test/a//b");
    }
}
