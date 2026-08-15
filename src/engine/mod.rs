use std::{collections::HashSet, path::Path};

use crate::{
    error::Result,
    fetcher::Fetcher,
    model::{EngineLimits, FetchMetadata, PolicySummary, Report, Rule, SerializableLimits},
    rules::RuleSelector,
};

mod reporting;
mod traversal;

/// Default concurrent package downloads and analyses.
pub const DEFAULT_ANALYSIS_THREADS: usize = 16;

/// Maximum configurable concurrent package downloads and analyses.
pub const MAX_ANALYSIS_THREADS: usize = 64;

/// Returns a safe package-work concurrency value.
#[must_use]
pub fn effective_analysis_threads(threads: usize) -> usize {
    threads.clamp(1, MAX_ANALYSIS_THREADS)
}

pub struct Engine<'a> {
    rules: &'a [Rule],
    fetcher: &'a dyn Fetcher,
    limits: EngineLimits,
    require_lockfile: bool,
    policy: PolicySummary,
    ignored_rule_selectors: Vec<RuleSelector>,
    ignored_packages: HashSet<String>,
    ignored_root_paths: Vec<String>,
    max_analysis_threads: usize,
}

impl<'a> Engine<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rules: &'a [Rule],
        fetcher: &'a dyn Fetcher,
        limits: EngineLimits,
        require_lockfile: bool,
        offline: bool,
        allowed_hosts: Vec<String>,
        trust_local_input: bool,
        allow_insecure_http: bool,
    ) -> Self {
        let policy = PolicySummary {
            require_lockfile,
            offline,
            trust_local_input,
            allow_insecure_http,
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
            max_analysis_threads: DEFAULT_ANALYSIS_THREADS,
        }
    }

    /// Limits the number of packages analyzed concurrently.
    ///
    /// Values below one are clamped to one, and larger values are capped at 64.
    #[must_use]
    pub fn with_max_analysis_threads(mut self, threads: usize) -> Self {
        self.max_analysis_threads = effective_analysis_threads(threads);
        self
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

    /// Analyzes multiple fetched roots in one acquisition and scan batch.
    ///
    /// Dependencies and source scans shared by multiple roots are performed once,
    /// while the returned reports retain each root's independent dependency closure.
    /// Aggregate unique roots and dependency fetch attempts are bounded by
    /// `EngineLimits::max_packages`. Reports are returned in the same order as `fetched`.
    pub async fn analyze_fetched_roots(&self, fetched: Vec<FetchMetadata>) -> Result<Vec<Report>> {
        self.analyze_with_fetched_roots(fetched).await
    }
}

#[cfg(test)]
mod tests;
