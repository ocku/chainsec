mod orchestration;
mod requests;

#[cfg(test)]
mod tests;

use std::collections::BTreeSet;

use crate::{manifests, model::OperationalIssue, scanner};

pub(super) struct ScanAndDiscovery {
    pub(super) scan: scanner::ScanOutcome,
    pub(super) discovery: manifests::Discovery,
    pub(super) python_contexts: BTreeSet<manifests::PythonLockContext>,
    pub(super) issues: Vec<OperationalIssue>,
}
