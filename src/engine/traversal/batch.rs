use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use futures::{StreamExt, stream};

use crate::{
    error::{Error, Result},
    model::{FetchMetadata, Report},
    scanner,
};

use super::{
    super::{
        Engine,
        reporting::{
            operational_issue, push_issue, record_install_scripts, record_package,
            record_shared_scan,
        },
    },
    state::{
        AcquisitionDecision, BatchTraversal, DiscoveredPackage, FetchKey, FetchRequest, ScanKey,
        canonicalize_root, merge_fetch_requests, pending_from_fetch,
        push_batch_package_limit_issue, push_package_limit_issue,
    },
};

type PreparedBatchFetch = (usize, FetchRequest, crate::fetcher::PreparedFetch);
type BatchFetchGroup = (FetchKey, Vec<PreparedBatchFetch>);
type BatchFetchResult = (
    FetchKey,
    Vec<PreparedBatchFetch>,
    std::result::Result<FetchMetadata, crate::model::OperationalIssue>,
);

impl Engine<'_> {
    pub(in crate::engine) async fn analyze_with_fetched_roots(
        &self,
        roots: Vec<FetchMetadata>,
    ) -> Result<Vec<Report>> {
        let mut traversals = self.initialize_batch_traversals(roots)?;
        let resources = Arc::new(scanner::AnalysisResources::new(
            self.rules,
            self.max_analysis_threads,
        )?);

        self.traverse_batch_dependencies(&mut traversals).await;

        let scans = self.scan_batch_packages(&traversals, resources).await?;
        Ok(self.finish_batch_reports(traversals, &scans))
    }

    fn initialize_batch_traversals(
        &self,
        roots: Vec<FetchMetadata>,
    ) -> Result<Vec<BatchTraversal>> {
        if roots.len() > self.limits.max_packages {
            return Err(Error::LimitExceeded {
                resource: "batch packages".to_owned(),
                limit: u64::try_from(self.limits.max_packages).unwrap_or(u64::MAX),
            });
        }

        roots
            .into_iter()
            .map(|fetched| {
                let root = canonicalize_root(&fetched.source)?;
                Ok(BatchTraversal::new(root, fetched, self.policy.clone()))
            })
            .collect()
    }

    async fn traverse_batch_dependencies(&self, traversals: &mut [BatchTraversal]) {
        let mut fetched_dependencies = HashMap::new();

        loop {
            let mut requests_by_root = Vec::with_capacity(traversals.len());
            let mut has_frontier = false;

            for batch in traversals.iter_mut() {
                match self.discover_frontier(batch).await {
                    Some(requests) => {
                        has_frontier = true;
                        requests_by_root.push(requests);
                    }
                    None => requests_by_root.push(Vec::new()),
                }
            }

            if !has_frontier {
                break;
            }

            self.fetch_batch_dependencies(requests_by_root, traversals, &mut fetched_dependencies)
                .await;
        }
    }

    async fn discover_frontier(&self, batch: &mut BatchTraversal) -> Option<Vec<FetchRequest>> {
        let frontier = batch
            .traversal
            .next_frontier(&mut batch.report, self.limits.max_packages)?;
        let discoveries = stream::iter(
            frontier
                .iter()
                .map(|pending| self.discover_package(pending)),
        )
        .buffered(self.max_analysis_threads)
        .collect::<Vec<_>>()
        .await;
        let mut requests = Vec::new();

        for (pending, (discovery, python_contexts, issues)) in frontier.into_iter().zip(discoveries)
        {
            batch.report.issues.extend(issues);
            if pending.depth < self.limits.max_package_depth {
                requests.extend(self.fetch_requests_for(
                    &pending,
                    &discovery,
                    python_contexts,
                    &mut batch.report,
                ));
            }
            if pending.report_source {
                batch
                    .packages
                    .push(DiscoveredPackage { pending, discovery });
            }
        }

        Some(merge_fetch_requests(requests))
    }

    fn finish_batch_reports(
        &self,
        traversals: Vec<BatchTraversal>,
        scans: &HashMap<
            ScanKey,
            std::result::Result<Arc<scanner::ScanOutcome>, crate::model::OperationalIssue>,
        >,
    ) -> Vec<Report> {
        traversals
            .into_iter()
            .map(|mut batch| {
                for package in batch.packages {
                    let key = ScanKey::new(&package.pending, &self.ignored_root_paths);
                    let scan_counts = match scans.get(&key).expect("every package has a batch scan")
                    {
                        Ok(scan) => record_shared_scan(&mut batch.report, scan),
                        Err(issue) => {
                            batch.report.issues.push(issue.clone());
                            (0, 0)
                        }
                    };
                    record_install_scripts(
                        &mut batch.report,
                        &package.pending,
                        &package.discovery.install_scripts,
                    );
                    record_package(
                        &mut batch.report,
                        &package.pending,
                        &package.discovery,
                        scan_counts,
                    );
                }
                self.finalize(&mut batch.report);
                batch.report
            })
            .collect()
    }

    async fn fetch_batch_dependencies(
        &self,
        requests_by_root: Vec<Vec<FetchRequest>>,
        traversals: &mut [BatchTraversal],
        fetched: &mut HashMap<
            FetchKey,
            std::result::Result<FetchMetadata, crate::model::OperationalIssue>,
        >,
    ) {
        let grouped = self.group_batch_fetches(requests_by_root, traversals, fetched);
        let unique_work = traversals.len().saturating_add(fetched.len());

        if grouped.len() > self.limits.max_packages.saturating_sub(unique_work) {
            self.report_batch_fetch_limit(grouped, traversals);
            return;
        }

        let results = self.fetch_batch_groups(grouped).await;
        self.apply_batch_fetch_results(results, traversals, fetched);
    }

    fn group_batch_fetches(
        &self,
        requests_by_root: Vec<Vec<FetchRequest>>,
        traversals: &mut [BatchTraversal],
        fetched: &HashMap<
            FetchKey,
            std::result::Result<FetchMetadata, crate::model::OperationalIssue>,
        >,
    ) -> Vec<BatchFetchGroup> {
        let mut grouped = Vec::<BatchFetchGroup>::new();
        let mut group_indices = HashMap::<FetchKey, usize>::new();
        let mut root_keys = vec![HashSet::<FetchKey>::new(); traversals.len()];
        let mut root_limit_reported = vec![false; traversals.len()];
        let mut revisited_requests = Vec::<(usize, FetchKey, FetchRequest)>::new();
        let mut revisited_request_indices = HashMap::<(usize, FetchKey), usize>::new();
        let mut fetched_requests = Vec::<(usize, FetchKey, FetchRequest)>::new();
        let mut fetched_request_indices = HashMap::<(usize, FetchKey), usize>::new();

        for (root_index, requests) in requests_by_root.into_iter().enumerate() {
            for request in requests {
                let prepared = match self
                    .fetcher
                    .prepare_fetch(request.dependency.clone(), request.declared_from.clone())
                {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        push_issue(
                            &mut traversals[root_index].report,
                            error,
                            Some(request.dependency.id()),
                            "fetch preparation",
                            false,
                        );
                        continue;
                    }
                };
                let key = FetchKey::new(&request, &prepared);
                let owner_key = (root_index, key.clone());

                if let Some(index) = revisited_request_indices.get(&owner_key).copied() {
                    revisited_requests[index]
                        .2
                        .contexts
                        .extend(request.contexts);
                    continue;
                }

                if root_keys[root_index].insert(key.clone()) {
                    if traversals[root_index]
                        .traversal
                        .pending_for_revisited_acquisition(&key, &request)
                        .is_some()
                    {
                        revisited_request_indices.insert(owner_key, revisited_requests.len());
                        revisited_requests.push((root_index, key, request));
                        continue;
                    }
                    match traversals[root_index]
                        .traversal
                        .reserve_acquisition(key.clone(), self.limits.max_packages)
                    {
                        AcquisitionDecision::Revisited => continue,
                        AcquisitionDecision::Reserved => {}
                        AcquisitionDecision::LimitExceeded => {
                            root_keys[root_index].remove(&key);
                            if !root_limit_reported[root_index] {
                                push_package_limit_issue(
                                    &mut traversals[root_index].report,
                                    request.declared_package_id.clone(),
                                    self.limits.max_packages as u64,
                                );
                                root_limit_reported[root_index] = true;
                            }
                            continue;
                        }
                    }
                }

                if fetched.contains_key(&key) {
                    let owner_key = (root_index, key.clone());
                    if let Some(index) = fetched_request_indices.get(&owner_key).copied() {
                        fetched_requests[index].2.contexts.extend(request.contexts);
                    } else {
                        fetched_request_indices.insert(owner_key, fetched_requests.len());
                        fetched_requests.push((root_index, key, request));
                    }
                    continue;
                }

                let group_index = *group_indices.entry(key.clone()).or_insert_with(|| {
                    grouped.push((key, Vec::new()));
                    grouped.len() - 1
                });
                if let Some((_, existing, _)) = grouped[group_index]
                    .1
                    .iter_mut()
                    .find(|(owner_root, _, _)| *owner_root == root_index)
                {
                    existing.contexts.extend(request.contexts);
                } else {
                    grouped[group_index].1.push((root_index, request, prepared));
                }
            }
        }

        for (root_index, key, request) in revisited_requests {
            if let Some(pending) = traversals[root_index]
                .traversal
                .pending_for_revisited_acquisition(&key, &request)
            {
                traversals[root_index].traversal.enqueue([pending]);
            }
        }

        for (root_index, key, request) in fetched_requests {
            let result = fetched
                .get(&key)
                .expect("cached batch fetch result must exist");
            self.apply_batch_fetch_result(root_index, &key, &request, result, traversals);
        }

        grouped
    }

    fn report_batch_fetch_limit(
        &self,
        grouped: Vec<BatchFetchGroup>,
        traversals: &mut [BatchTraversal],
    ) {
        for (_, owners) in grouped {
            for (root_index, request, _) in owners {
                push_batch_package_limit_issue(
                    &mut traversals[root_index].report,
                    request.declared_package_id,
                    self.limits.max_packages as u64,
                );
            }
        }
    }

    async fn fetch_batch_groups(&self, grouped: Vec<BatchFetchGroup>) -> Vec<BatchFetchResult> {
        stream::iter(grouped)
            .map(|(key, owners)| async move {
                let request = &owners[0].1;
                let dependency_id = request.dependency.id();
                let result = self
                    .fetcher
                    .fetch_prepared(owners[0].2.clone())
                    .await
                    .map_err(|error| operational_issue(error, Some(dependency_id), "fetch", false));
                (key, owners, result)
            })
            .buffered(self.max_analysis_threads)
            .collect()
            .await
    }

    fn apply_batch_fetch_results(
        &self,
        results: Vec<BatchFetchResult>,
        traversals: &mut [BatchTraversal],
        fetched: &mut HashMap<
            FetchKey,
            std::result::Result<FetchMetadata, crate::model::OperationalIssue>,
        >,
    ) {
        for (key, owners, result) in results {
            for (root_index, request, _) in &owners {
                self.apply_batch_fetch_result(*root_index, &key, request, &result, traversals);
            }
            fetched.insert(key, result);
        }
    }

    fn apply_batch_fetch_result(
        &self,
        root_index: usize,
        key: &FetchKey,
        request: &FetchRequest,
        result: &std::result::Result<FetchMetadata, crate::model::OperationalIssue>,
        traversals: &mut [BatchTraversal],
    ) {
        match result {
            Ok(metadata) => {
                traversals[root_index]
                    .traversal
                    .record_successful_acquisition(key.clone(), metadata.clone());
                traversals[root_index]
                    .traversal
                    .enqueue([pending_from_fetch(request, metadata.clone())]);
            }
            Err(issue) => traversals[root_index].report.issues.push(issue.clone()),
        }
    }

    async fn scan_batch_packages(
        &self,
        traversals: &[BatchTraversal],
        resources: Arc<scanner::AnalysisResources>,
    ) -> Result<
        HashMap<
            ScanKey,
            std::result::Result<Arc<scanner::ScanOutcome>, crate::model::OperationalIssue>,
        >,
    > {
        let mut keys = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for batch in traversals {
            for package in &batch.packages {
                let key = ScanKey::new(&package.pending, &self.ignored_root_paths);
                if seen.insert(key.clone()) {
                    keys.push(key);
                }
            }
        }

        let scans = stream::iter(keys).map(|key| {
            let resources = Arc::clone(&resources);
            async move {
                let result = scanner::scan_async(
                    key.source.clone(),
                    key.package_id.clone(),
                    resources,
                    self.limits.clone(),
                    key.ignored_paths.clone(),
                    key.exclude_node_modules,
                )
                .await
                .map(Arc::new)
                .map_err(|error| {
                    operational_issue(error, Some(key.package_id.clone()), "scan", false)
                });
                (key, result)
            }
        });

        Ok(scans
            .buffered(self.max_analysis_threads)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect())
    }
}
