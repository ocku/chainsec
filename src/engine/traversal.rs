use std::{
    collections::{HashSet, VecDeque},
    fs,
    path::{Path, PathBuf},
};

use futures::{StreamExt, stream};

use crate::{
    error::{Error, Result},
    manifests,
    model::{Dependency, FetchMetadata, Report},
    scanner,
};

use super::{
    Engine,
    reporting::{
        finalize_report, operational_issue, push_issue, record_capabilities,
        record_install_scripts, record_package, record_scan,
    },
};

const MAX_CONCURRENT_FETCHES: usize = 16;
const MAX_CONCURRENT_PACKAGE_ANALYSES: usize = 8;

fn package_analysis_concurrency() -> usize {
    std::thread::available_parallelism()
        .map(|parallelism| parallelism.get())
        .unwrap_or(1)
        .min(MAX_CONCURRENT_PACKAGE_ANALYSES)
}

pub(super) struct PendingPackage {
    pub(super) package_id: String,
    pub(super) source: PathBuf,
    pub(super) depth: usize,
    pub(super) fetched: Option<FetchMetadata>,
    npm_context: Option<manifests::NpmLockContext>,
    python_context: Option<manifests::PythonLockContext>,
}

struct ScanAndDiscovery {
    scan: scanner::ScanOutcome,
    discovery: manifests::Discovery,
    python_context: Option<manifests::PythonLockContext>,
    issues: Vec<crate::model::OperationalIssue>,
}

struct FetchRequest {
    dependency: Dependency,
    npm_context: Option<manifests::NpmLockContext>,
    python_context: Option<manifests::PythonLockContext>,
    declared_from: PathBuf,
    declared_package_id: String,
    depth: usize,
}

struct Traversal {
    queue: VecDeque<PendingPackage>,
    visited: HashSet<String>,
}

impl PendingPackage {
    fn root(source: PathBuf, fetched: Option<FetchMetadata>) -> Self {
        Self {
            package_id: "root".to_owned(),
            source,
            depth: 0,
            fetched,
            npm_context: None,
            python_context: None,
        }
    }
}

impl Traversal {
    fn new(root: PathBuf, fetched: Option<FetchMetadata>) -> Self {
        Self {
            queue: VecDeque::from([PendingPackage::root(root, fetched)]),
            visited: HashSet::new(),
        }
    }

    fn next_frontier(
        &mut self,
        report: &mut Report,
        package_limit: usize,
    ) -> Option<Vec<PendingPackage>> {
        let depth = self.queue.front()?.depth;
        let mut frontier = Vec::new();

        while self
            .queue
            .front()
            .is_some_and(|pending| pending.depth == depth)
        {
            let pending = self.queue.pop_front().expect("frontier entry must exist");
            if !self.visited.insert(pending.package_id.clone()) {
                continue;
            }

            if self.visited.len() > package_limit {
                push_package_limit_issue(report, pending.package_id, package_limit as u64);
                break;
            }
            frontier.push(pending);
        }

        (!frontier.is_empty()).then_some(frontier)
    }

    fn enqueue(&mut self, packages: impl IntoIterator<Item = PendingPackage>) {
        self.queue.extend(packages);
    }

    fn visited_count(&self) -> usize {
        self.visited.len()
    }
}

impl Engine<'_> {
    pub(super) async fn analyze_with_root(
        &self,
        root: &Path,
        fetched: Option<FetchMetadata>,
    ) -> Result<Report> {
        let root = canonicalize_root(root)?;
        let mut report = Report::new(root.clone(), self.policy.clone());
        let mut traversal = Traversal::new(root, fetched);

        while let Some(frontier) = traversal.next_frontier(&mut report, self.limits.max_packages) {
            let fetch_requests = self.analyze_frontier(frontier, &mut report).await;
            let fetch_requests = limit_fetch_requests(
                fetch_requests,
                &mut report,
                traversal.visited_count(),
                self.limits.max_packages,
            );
            traversal.enqueue(self.fetch_dependencies(fetch_requests, &mut report).await);
        }

        report.findings.retain(|finding| {
            !self
                .ignored_rule_selectors
                .iter()
                .any(|selector| selector.matches_finding(finding))
        });
        record_capabilities(&mut report);
        finalize_report(&mut report);
        Ok(report)
    }

    async fn analyze_frontier(
        &self,
        frontier: Vec<PendingPackage>,
        report: &mut Report,
    ) -> Vec<FetchRequest> {
        let analyses = stream::iter(
            frontier
                .iter()
                .map(|pending| self.scan_and_discover(pending)),
        )
        .buffered(package_analysis_concurrency())
        .collect::<Vec<_>>()
        .await;
        let mut fetch_requests = Vec::new();

        for (pending, analysis) in frontier.into_iter().zip(analyses) {
            report.issues.extend(analysis.issues);
            let scan_counts = record_scan(report, analysis.scan);
            record_install_scripts(report, &pending, &analysis.discovery.install_scripts);
            record_package(report, &pending, &analysis.discovery, scan_counts);

            if pending.depth < self.limits.max_depth {
                fetch_requests.extend(self.fetch_requests_for(
                    &pending,
                    &analysis.discovery,
                    analysis.python_context,
                    report,
                ));
            }
        }

        fetch_requests
    }

    fn fetch_requests_for(
        &self,
        pending: &PendingPackage,
        discovery: &manifests::Discovery,
        python_context: Option<manifests::PythonLockContext>,
        report: &mut Report,
    ) -> impl Iterator<Item = FetchRequest> {
        self.filter_fetchable_dependencies(pending, discovery, report)
            .into_iter()
            .filter(|(dependency, _)| {
                !self
                    .ignored_packages
                    .contains(&ignored_package_id(dependency))
            })
            .map(move |(dependency, npm_context)| FetchRequest {
                dependency,
                npm_context,
                python_context: python_context.clone(),
                declared_from: pending.source.clone(),
                declared_package_id: pending.package_id.clone(),
                depth: pending.depth + 1,
            })
    }

    async fn fetch_dependencies(
        &self,
        requests: Vec<FetchRequest>,
        report: &mut Report,
    ) -> Vec<PendingPackage> {
        let fetches = stream::iter(requests).map(|request| async move {
            let dependency_id = request.dependency.id();
            let result = self
                .fetcher
                .fetch(request.dependency, request.declared_from)
                .await;
            (
                result,
                dependency_id,
                request.npm_context,
                request.python_context,
                request.depth,
            )
        });
        let mut fetches = fetches.buffered(MAX_CONCURRENT_FETCHES);
        let mut packages = Vec::new();

        while let Some((result, dependency_id, npm_context, python_context, depth)) =
            fetches.next().await
        {
            match result {
                Ok(metadata) => packages.push(PendingPackage {
                    package_id: metadata.package_id.clone(),
                    source: metadata.source.clone(),
                    depth,
                    fetched: Some(metadata),
                    npm_context,
                    python_context,
                }),
                Err(error) => push_issue(report, error, Some(dependency_id), "fetch", false),
            }
        }

        packages
    }

    async fn scan_and_discover(&self, pending: &PendingPackage) -> ScanAndDiscovery {
        let scan_task = async {
            scanner::scan_async(
                pending.source.clone(),
                pending.package_id.clone(),
                self.rules.to_vec(),
                self.limits.clone(),
                if pending.depth == 0 {
                    self.ignored_root_paths.clone()
                } else {
                    Vec::new()
                },
            )
            .await
        };
        let discovery_source = pending.source.clone();
        let npm_context = pending.npm_context.clone();
        let python_context = pending.python_context.clone();
        let discovery_task = tokio::task::spawn_blocking(move || {
            manifests::discover_with_contexts(
                &discovery_source,
                npm_context.as_ref(),
                python_context.as_ref(),
            )
        });
        let (scan_result, discovery_result) = tokio::join!(scan_task, discovery_task);

        let mut issues = Vec::new();
        let scan = scan_result.unwrap_or_else(|error| {
            issues.push(operational_issue(
                error,
                Some(pending.package_id.clone()),
                "scan",
                false,
            ));
            scanner::ScanOutcome::default()
        });
        let (discovery, python_context) = match discovery_result {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                issues.push(operational_issue(
                    error,
                    Some(pending.package_id.clone()),
                    "manifest discovery",
                    false,
                ));
                empty_discovery()
            }
            Err(error) => {
                issues.push(operational_issue(
                    Error::Manifest {
                        path: pending.source.clone(),
                        message: format!("manifest discovery worker failed: {error}"),
                    },
                    Some(pending.package_id.clone()),
                    "manifest discovery",
                    false,
                ));
                empty_discovery()
            }
        };

        ScanAndDiscovery {
            scan,
            discovery,
            python_context,
            issues,
        }
    }

    fn filter_fetchable_dependencies(
        &self,
        pending: &PendingPackage,
        discovery: &manifests::Discovery,
        report: &mut Report,
    ) -> Vec<(Dependency, Option<manifests::NpmLockContext>)> {
        discovery
            .dependencies
            .iter()
            .filter_map(|dependency| {
                if self.require_lockfile && !dependency.is_resolved() {
                    push_issue(
                        report,
                        Error::Policy {
                            operation: "dependency resolution".to_owned(),
                            message: format!(
                                "{} is not fully resolved by a supported lockfile",
                                dependency.id()
                            ),
                        },
                        Some(pending.package_id.clone()),
                        "resolution",
                        false,
                    );
                    return None;
                }

                Some((
                    dependency.clone(),
                    discovery.npm_contexts.get(&dependency.id()).cloned(),
                ))
            })
            .collect()
    }
}

fn limit_fetch_requests(
    mut requests: Vec<FetchRequest>,
    report: &mut Report,
    visited_packages: usize,
    package_limit: usize,
) -> Vec<FetchRequest> {
    let mut dependency_ids = HashSet::new();
    requests.retain(|request| dependency_ids.insert(request.dependency.id()));

    let remaining_packages = package_limit.saturating_sub(visited_packages);
    if requests.len() > remaining_packages {
        push_package_limit_issue(
            report,
            requests[remaining_packages].declared_package_id.clone(),
            package_limit as u64,
        );
        requests.truncate(remaining_packages);
    }

    requests
}

fn canonicalize_root(root: &Path) -> Result<PathBuf> {
    fs::canonicalize(root).map_err(|source| Error::Io {
        operation: "canonicalize project root".to_owned(),
        path: root.to_owned(),
        source,
    })
}

fn empty_discovery() -> (manifests::Discovery, Option<manifests::PythonLockContext>) {
    (
        manifests::Discovery {
            dependencies: Vec::new(),
            lockfiles: Vec::new(),
            install_scripts: Vec::new(),
            npm_contexts: Default::default(),
        },
        None,
    )
}

fn push_package_limit_issue(report: &mut Report, package_id: String, limit: u64) {
    push_issue(
        report,
        Error::LimitExceeded {
            resource: "packages".to_owned(),
            limit,
        },
        Some(package_id),
        "traversal",
        true,
    );
}

fn ignored_package_id(dependency: &Dependency) -> String {
    let version = dependency
        .resolved_version
        .as_deref()
        .unwrap_or(&dependency.requirement);
    format!("{}:{}@{version}", dependency.ecosystem, dependency.name)
}
