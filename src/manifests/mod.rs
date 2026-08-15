use std::{
    collections::{BTreeSet, HashMap},
    path::PathBuf,
};

use crate::model::{Dependency, Language};

mod deno;
mod discovery;
mod npm;
mod python;
pub(crate) mod shared;

#[cfg(test)]
use deno::strip_jsonc;
pub use discovery::discover;
pub(crate) use discovery::discover_with_contexts_and_limits;
pub(crate) use python::PythonLockContext;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    pub(crate) npm_contexts: HashMap<String, BTreeSet<NpmLockContext>>,
}

pub(crate) struct DiscoveryOutcome {
    pub(crate) discovery: Discovery,
    pub(crate) python_contexts: BTreeSet<PythonLockContext>,
    pub(crate) errors: Vec<crate::error::Error>,
}
