use std::{collections::HashSet, path::Path};

use crate::{
    error::Result,
    fetcher::Fetcher,
    model::{EngineLimits, FetchMetadata, PolicySummary, Report, Rule},
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
    pub fn new(rules: &'a [Rule], fetcher: &'a dyn Fetcher, policy: PolicySummary) -> Self {
        Self {
            rules,
            fetcher,
            limits: engine_limits_from_policy(&policy),
            require_lockfile: policy.require_lockfile,
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

/// Derives engine runtime limits from a serializable policy summary. The
/// summary is the source of truth for report serialization, so keeping a single
/// policy object avoids the limits drifting apart from what is reported.
fn engine_limits_from_policy(policy: &PolicySummary) -> EngineLimits {
    EngineLimits {
        max_package_depth: policy.limits.max_package_depth,
        max_packages: policy.limits.max_packages,
        max_network_requests: policy.limits.max_network_requests,
        max_redirect_hops: policy.limits.max_redirect_hops,
        request_timeout: std::time::Duration::from_secs(policy.limits.request_timeout_seconds),
        max_acquisition_duration: std::time::Duration::from_secs(
            policy.limits.max_acquisition_seconds,
        ),
        max_archive_size: policy.limits.max_archive_size,
        max_extracted_size: policy.limits.max_extracted_size,
        max_extracted_files: policy.limits.max_extracted_files,
        max_file_depth: policy.limits.max_file_depth,
        max_manifest_file_size: policy.limits.max_manifest_file_size,
        max_source_file_size: policy.limits.max_source_file_size,
        max_source_files: policy.limits.max_source_files,
        max_findings: policy.limits.max_findings,
        max_scan_duration: std::time::Duration::from_secs(policy.limits.max_scan_seconds),
        fail_on_parse_error: policy.limits.fail_on_parse_error,
    }
}

#[cfg(test)]
mod tests;
