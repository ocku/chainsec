use std::{collections::HashSet, path::Path};

use crate::{
    error::Result,
    fetcher::Fetcher,
    model::{EngineLimits, FetchMetadata, PolicySummary, Report, Rule, SerializableLimits},
    rules::RuleSelector,
};

mod reporting;
mod traversal;

pub struct Engine<'a> {
    rules: &'a [Rule],
    fetcher: &'a dyn Fetcher,
    limits: EngineLimits,
    require_lockfile: bool,
    policy: PolicySummary,
    ignored_rule_selectors: Vec<RuleSelector>,
    ignored_packages: HashSet<String>,
    ignored_root_paths: Vec<String>,
}

impl<'a> Engine<'a> {
    pub fn new(
        rules: &'a [Rule],
        fetcher: &'a dyn Fetcher,
        limits: EngineLimits,
        require_lockfile: bool,
        offline: bool,
        allowed_hosts: Vec<String>,
        trust_local_input: bool,
    ) -> Self {
        let policy = PolicySummary {
            require_lockfile,
            offline,
            trust_local_input,
            allowed_hosts,
            limits: SerializableLimits::from(&limits),
        };

        Self {
            rules,
            fetcher,
            limits,
            require_lockfile,
            policy,
            ignored_rule_selectors: Vec::new(),
            ignored_packages: HashSet::new(),
            ignored_root_paths: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_ignored_rule_selectors(
        mut self,
        selectors: impl IntoIterator<Item = RuleSelector>,
    ) -> Self {
        self.ignored_rule_selectors.extend(selectors);
        self
    }

    #[must_use]
    pub fn with_ignored_packages(mut self, packages: impl IntoIterator<Item = String>) -> Self {
        self.ignored_packages.extend(packages);
        self
    }

    #[must_use]
    pub fn with_ignored_root_paths(mut self, paths: impl IntoIterator<Item = String>) -> Self {
        self.ignored_root_paths.extend(paths);
        self
    }

    pub async fn analyze(&self, root: &Path) -> Result<Report> {
        self.analyze_with_root(root, None).await
    }

    /// Analyzes an explicitly fetched package as the traversal root.
    pub async fn analyze_fetched_root(&self, fetched: FetchMetadata) -> Result<Report> {
        let source = fetched.source.clone();
        self.analyze_with_root(&source, Some(fetched)).await
    }
}

#[cfg(test)]
mod tests;
