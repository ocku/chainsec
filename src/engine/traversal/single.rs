use std::{collections::HashMap, path::Path, sync::Arc, time::Instant};

use futures::{StreamExt, stream};
use tracing::debug;

use crate::{
    error::Result,
    model::{FetchMetadata, Report},
    scanner,
};

use super::{
    super::{
        Engine,
        reporting::{
            finalize_report, push_issue, record_capabilities, record_install_scripts,
            record_package, record_scan,
        },
    },
    state::{
        FetchKey, FetchRequest, MAX_CONCURRENT_FETCHES, PendingPackage, Traversal,
        canonicalize_root, push_package_limit_issue,
    },
};

impl Engine<'_> {
    pub(in crate::engine) async fn analyze_with_root(
        &self,
        root: &Path,
        fetched: Option<FetchMetadata>,
    ) -> Result<Report> {
        let root = canonicalize_root(root)?;
        let mut report = Report::new(root.clone(), self.policy.clone());
        let resources = Arc::new(scanner::AnalysisResources::new(
            self.rules,
            self.max_analysis_threads,
        )?);
        let mut traversal = Traversal::new(root, fetched);

        while let Some(frontier) = traversal.next_frontier(&mut report, self.limits.max_packages) {
            let frontier_packages = frontier.len();
            let started = Instant::now();
            let fetch_requests = self
                .analyze_frontier(frontier, &mut report, Arc::clone(&resources))
                .await;
            debug!(
                packages = frontier_packages,
                fetch_requests = fetch_requests.len(),
                elapsed_ms = started.elapsed().as_millis(),
                "analyzed dependency frontier"
            );
            let started = Instant::now();
            let (packages, fetch_attempts) = self
                .fetch_dependencies(
                    fetch_requests,
                    &mut report,
                    traversal.remaining_fetch_attempts(self.limits.max_packages),
                )
                .await;
            debug!(
                fetch_attempts,
                packages = packages.len(),
                elapsed_ms = started.elapsed().as_millis(),
                "fetched dependency frontier"
            );
            traversal.record_fetch_attempts(fetch_attempts);
            traversal.enqueue(packages);
        }

        self.finalize(&mut report);
        Ok(report)
    }

    pub(super) fn finalize(&self, report: &mut Report) {
        report.findings.retain(|finding| {
            !self
                .ignored_rule_selectors
                .iter()
                .any(|selector| selector.matches_finding(finding))
        });
        record_capabilities(report);
        finalize_report(report);
    }

    async fn analyze_frontier(
        &self,
        frontier: Vec<PendingPackage>,
        report: &mut Report,
        resources: Arc<scanner::AnalysisResources>,
    ) -> Vec<FetchRequest> {
        let analyses = stream::iter(
            frontier
                .iter()
                .map(|pending| self.scan_and_discover(pending, Arc::clone(&resources))),
        )
        .buffered(self.max_analysis_threads)
        .collect::<Vec<_>>()
        .await;
        let mut fetch_requests = Vec::new();

        for (pending, analysis) in frontier.into_iter().zip(analyses) {
            report.issues.extend(analysis.issues);
            if pending.report_source {
                let scan_counts = record_scan(report, analysis.scan);
                record_install_scripts(report, &pending, &analysis.discovery.install_scripts);
                record_package(report, &pending, &analysis.discovery, scan_counts);
            }

            if pending.depth < self.limits.max_package_depth {
                fetch_requests.extend(self.fetch_requests_for(
                    &pending,
                    &analysis.discovery,
                    analysis.python_contexts,
                    report,
                ));
            }
        }

        fetch_requests
    }

    async fn fetch_dependencies(
        &self,
        requests: Vec<FetchRequest>,
        report: &mut Report,
        remaining_fetch_attempts: usize,
    ) -> (Vec<PendingPackage>, usize) {
        let mut grouped = Vec::<(FetchKey, FetchRequest, crate::fetcher::PreparedFetch)>::new();
        let mut group_indices = HashMap::<FetchKey, usize>::new();
        for request in requests {
            let prepared = match self
                .fetcher
                .prepare_fetch(request.dependency.clone(), request.declared_from.clone())
            {
                Ok(prepared) => prepared,
                Err(error) => {
                    push_issue(
                        report,
                        error,
                        Some(request.dependency.id()),
                        "fetch preparation",
                        false,
                    );
                    continue;
                }
            };
            let key = FetchKey::new(&request, &prepared);
            if let Some(index) = group_indices.get(&key).copied() {
                grouped[index].1.contexts.extend(request.contexts);
            } else {
                let index = grouped.len();
                group_indices.insert(key.clone(), index);
                grouped.push((key, request, prepared));
            }
        }

        if grouped.len() > remaining_fetch_attempts {
            push_package_limit_issue(
                report,
                grouped[remaining_fetch_attempts]
                    .1
                    .declared_package_id
                    .clone(),
                self.limits.max_packages as u64,
            );
            grouped.truncate(remaining_fetch_attempts);
        }
        let fetch_attempts = grouped.len();

        let fetches = stream::iter(grouped).map(|(_, request, prepared)| async move {
            let dependency_id = request.dependency.id();
            let result = self.fetcher.fetch_prepared(prepared).await;
            (result, dependency_id, request.contexts, request.depth)
        });
        let mut fetches = fetches.buffered(MAX_CONCURRENT_FETCHES);
        let mut packages = Vec::new();

        while let Some((result, dependency_id, contexts, depth)) = fetches.next().await {
            match result {
                Ok(metadata) => packages.push(PendingPackage {
                    package_id: metadata.package_id.clone(),
                    source: metadata.source.clone(),
                    depth,
                    fetched: Some(metadata),
                    contexts,
                    report_source: true,
                }),
                Err(error) => push_issue(report, error, Some(dependency_id), "fetch", false),
            }
        }

        (packages, fetch_attempts)
    }
}
