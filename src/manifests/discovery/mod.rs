use std::path::Path;

use super::{Discovery, DiscoveryOutcome, NpmLockContext, PythonLockContext};
use crate::{error::Result, model::EngineLimits};

mod contexts;
mod deno;
mod npm;
mod orchestration;
mod python;

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
    orchestration::discover_with_contexts(root, inherited_npm_contexts, inherited_python_contexts)
}

pub(crate) fn discover_with_contexts_and_limits(
    root: &Path,
    inherited_npm_contexts: &[NpmLockContext],
    inherited_python_contexts: &[PythonLockContext],
    limits: &EngineLimits,
) -> DiscoveryOutcome {
    orchestration::discover_with_contexts_and_limits(
        root,
        inherited_npm_contexts,
        inherited_python_contexts,
        limits,
    )
}

#[cfg(test)]
mod tests;
