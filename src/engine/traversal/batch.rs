use std::{collections::HashMap, sync::Arc};

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
        BatchTraversal, DiscoveredPackage, FetchKey, FetchRequest, MAX_CONCURRENT_FETCHES, ScanKey,
        canonicalize_root, limit_fetch_requests, pending_from_fetch,
        push_batch_package_limit_issue,
    },
};

impl Engine<'_> {
    pub(in crate::engine) async fn analyze_with_fetched_roots(
        &self,
        roots: Vec<FetchMetadata>,
    ) -> Result<Vec<Report>> {
        if roots.len() > self.limits.max_packages {
            return Err(Error::LimitExceeded {
                resource: "batch packages".to_owned(),
                limit: u64::try_from(self.limits.max_packages).unwrap_or(u64::MAX),
            });
        }
        let mut traversals = roots
            .into_iter()
            .map(|fetched| {
                let root = canonicalize_root(&fetched.source)?;
                Ok(BatchTraversal::new(root, fetched, self.policy.clone()))
            })
            .collect::<Result<Vec<_>>>()?;
        let resources = Arc::new(scanner::AnalysisResources::new(
            self.rules,
            self.max_analysis_threads,
        )?);
        let mut fetched_dependencies = HashMap::new();

        loop {
            let mut requests_by_root = Vec::with_capacity(traversals.len());
            let mut has_frontier = false;

            for batch in &mut traversals {
                let Some(frontier) = batch
                    .traversal
                    .next_frontier(&mut batch.report, self.limits.max_packages)
                else {
                    requests_by_root.push(Vec::new());
                    continue;
                };
                has_frontier = true;
                let discoveries = stream::iter(
                    frontier
                        .iter()
                        .map(|pending| self.discover_package(pending)),
                )
                .buffered(self.max_analysis_threads)
                .collect::<Vec<_>>()
                .await;
                let mut requests = Vec::new();

                for (pending, (discovery, python_contexts, issues)) in
                    frontier.into_iter().zip(discoveries)
                {
                    batch.report.issues.extend(issues);
                    if pending.depth < self.limits.max_depth {
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

                requests_by_root.push(limit_fetch_requests(
                    requests,
                    &mut batch.report,
                    batch.traversal.visited_count(),
                    self.limits.max_packages,
                ));
            }

            if !has_frontier {
                break;
            }

            self.fetch_batch_dependencies(
                requests_by_root,
                &mut traversals,
                &mut fetched_dependencies,
            )
            .await;
        }

        let scans = self.scan_batch_packages(&traversals, resources).await?;
        let mut reports = Vec::with_capacity(traversals.len());
        for mut batch in traversals {
            for package in batch.packages {
                let key = ScanKey::new(&package.pending, &self.ignored_root_paths);
                let scan_counts = match scans.get(&key).expect("every package has a batch scan") {
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
            reports.push(batch.report);
        }

        Ok(reports)
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
        let mut grouped = Vec::<(
            FetchKey,
            Vec<(usize, FetchRequest, crate::fetcher::PreparedFetch)>,
        )>::new();
        let mut group_indices = HashMap::new();

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
                if let Some(result) = fetched.get(&key) {
                    match result {
                        Ok(metadata) => traversals[root_index]
                            .traversal
                            .enqueue([pending_from_fetch(&request, metadata.clone())]),
                        Err(issue) => traversals[root_index].report.issues.push(issue.clone()),
                    }
                    continue;
                }

                let group_index = *group_indices.entry(key.clone()).or_insert_with(|| {
                    grouped.push((key, Vec::new()));
                    grouped.len() - 1
                });
                grouped[group_index].1.push((root_index, request, prepared));
            }
        }

        let unique_work = traversals.len().saturating_add(fetched.len());
        if grouped.len() > self.limits.max_packages.saturating_sub(unique_work) {
            for (_, owners) in grouped {
                for (root_index, request, _) in owners {
                    push_batch_package_limit_issue(
                        &mut traversals[root_index].report,
                        request.declared_package_id,
                        self.limits.max_packages as u64,
                    );
                }
            }
            return;
        }

        let fetches = stream::iter(grouped).map(|(key, owners)| async move {
            let request = &owners[0].1;
            let dependency_id = request.dependency.id();
            let result = self
                .fetcher
                .fetch_prepared(owners[0].2.clone())
                .await
                .map_err(|error| operational_issue(error, Some(dependency_id), "fetch", false));
            (key, owners, result)
        });
        let results = fetches
            .buffered(MAX_CONCURRENT_FETCHES)
            .collect::<Vec<_>>()
            .await;

        for (key, owners, result) in results {
            for (root_index, request, _) in &owners {
                match &result {
                    Ok(metadata) => traversals[*root_index]
                        .traversal
                        .enqueue([pending_from_fetch(request, metadata.clone())]),
                    Err(issue) => traversals[*root_index].report.issues.push(issue.clone()),
                }
            }
            fetched.insert(key, result);
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
