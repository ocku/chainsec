use std::{
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
    fs,
    path::{Path, PathBuf},
};

use crate::{
    error::{Error, Result},
    manifests,
    model::{Dependency, FetchMetadata, Report},
};

use super::super::reporting::push_issue;

pub(super) const MAX_CONCURRENT_FETCHES: usize = crate::engine::MAX_ANALYSIS_THREADS;

#[derive(Clone, Default)]
pub(super) struct DiscoveryContexts {
    pub(super) npm: BTreeSet<manifests::NpmLockContext>,
    pub(super) python: BTreeSet<manifests::PythonLockContext>,
}

impl DiscoveryContexts {
    pub(super) fn extend(&mut self, other: Self) {
        self.npm.extend(other.npm);
        self.python.extend(other.python);
    }

    fn retain_unvisited(&mut self, visited: &Self) {
        self.npm.retain(|context| !visited.npm.contains(context));
        self.python
            .retain(|context| !visited.python.contains(context));
    }

    fn is_empty(&self) -> bool {
        self.npm.is_empty() && self.python.is_empty()
    }
}

pub(in crate::engine) struct PendingPackage {
    pub(in crate::engine) package_id: String,
    pub(in crate::engine) source: PathBuf,
    pub(in crate::engine) depth: usize,
    pub(in crate::engine) fetched: Option<FetchMetadata>,
    pub(super) contexts: DiscoveryContexts,
    pub(super) report_source: bool,
}

pub(super) struct FetchRequest {
    pub(super) dependency: Dependency,
    pub(super) contexts: DiscoveryContexts,
    pub(super) declared_from: PathBuf,
    pub(super) declared_package_id: String,
    pub(super) depth: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct FetchKey {
    pub(super) package_id: String,
    requirement: String,
    source_url: Option<String>,
    declared_from: Option<PathBuf>,
    acquisition_identity: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct ScanKey {
    pub(super) source: PathBuf,
    pub(super) package_id: String,
    pub(super) ignored_paths: Vec<String>,
    pub(super) exclude_node_modules: bool,
}

pub(super) struct DiscoveredPackage {
    pub(super) pending: PendingPackage,
    pub(super) discovery: manifests::Discovery,
}

pub(super) struct BatchTraversal {
    pub(super) traversal: Traversal,
    pub(super) report: Report,
    pub(super) packages: Vec<DiscoveredPackage>,
}

pub(super) struct Traversal {
    queue: VecDeque<PendingPackage>,
    visited_package_ids: HashSet<String>,
    visited_sources: HashSet<PathBuf>,
    visited_contexts: HashMap<PathBuf, DiscoveryContexts>,
    visited_count: usize,
    fetch_attempt_count: usize,
}

impl FetchKey {
    pub(super) fn new(request: &FetchRequest, prepared: &crate::fetcher::PreparedFetch) -> Self {
        Self {
            package_id: request.dependency.id(),
            requirement: request.dependency.requirement.clone(),
            source_url: request.dependency.source_url.clone(),
            declared_from: request
                .dependency
                .is_local()
                .then(|| request.declared_from.clone()),
            acquisition_identity: prepared.acquisition_identity.clone(),
        }
    }
}

impl ScanKey {
    pub(super) fn new(pending: &PendingPackage, ignored_root_paths: &[String]) -> Self {
        Self {
            source: pending.source.clone(),
            package_id: pending.package_id.clone(),
            ignored_paths: if pending.depth == 0 {
                ignored_root_paths.to_vec()
            } else {
                Vec::new()
            },
            exclude_node_modules: pending.fetched.is_none(),
        }
    }
}

impl PendingPackage {
    fn root(source: PathBuf, fetched: Option<FetchMetadata>) -> Self {
        let package_id = fetched
            .as_ref()
            .map_or_else(|| "root".to_owned(), |metadata| metadata.package_id.clone());
        Self {
            package_id,
            source,
            depth: 0,
            fetched,
            contexts: DiscoveryContexts::default(),
            report_source: true,
        }
    }

    fn resolved_package_id(&self) -> &str {
        self.fetched
            .as_ref()
            .map_or(&self.package_id, |metadata| &metadata.package_id)
    }
}

impl BatchTraversal {
    pub(super) fn new(
        root: PathBuf,
        fetched: FetchMetadata,
        policy: crate::model::PolicySummary,
    ) -> Self {
        Self {
            traversal: Traversal::new(root.clone(), Some(fetched)),
            report: Report::new(root, policy),
            packages: Vec::new(),
        }
    }
}

impl Traversal {
    pub(super) fn new(root: PathBuf, fetched: Option<FetchMetadata>) -> Self {
        Self {
            queue: VecDeque::from([PendingPackage::root(root, fetched)]),
            visited_package_ids: HashSet::new(),
            visited_sources: HashSet::new(),
            visited_contexts: HashMap::new(),
            visited_count: 0,
            fetch_attempt_count: 0,
        }
    }

    pub(super) fn next_frontier(
        &mut self,
        report: &mut Report,
        package_limit: usize,
    ) -> Option<Vec<PendingPackage>> {
        let depth = self.queue.front()?.depth;
        let mut merged = Vec::<PendingPackage>::new();

        while self
            .queue
            .front()
            .is_some_and(|pending| pending.depth == depth)
        {
            let pending = self.queue.pop_front().expect("frontier entry must exist");
            if let Some(existing) = merged.iter_mut().find(|existing| {
                existing.resolved_package_id() == pending.resolved_package_id()
                    || existing.source == pending.source
            }) {
                existing.contexts.extend(pending.contexts);
                continue;
            }
            merged.push(pending);
        }

        let mut frontier = Vec::new();
        for mut pending in merged {
            let visited = self
                .visited_package_ids
                .contains(pending.resolved_package_id())
                || self.visited_sources.contains(&pending.source);
            if visited {
                let visited_contexts = self
                    .visited_contexts
                    .entry(pending.source.clone())
                    .or_default();
                pending.contexts.retain_unvisited(visited_contexts);
                if pending.contexts.is_empty() {
                    continue;
                }
                visited_contexts.extend(pending.contexts.clone());
                pending.report_source = false;
                frontier.push(pending);
                continue;
            }

            self.visited_package_ids
                .insert(pending.resolved_package_id().to_owned());
            self.visited_sources.insert(pending.source.clone());
            self.visited_contexts
                .entry(pending.source.clone())
                .or_default()
                .extend(pending.contexts.clone());
            self.visited_count += 1;

            if self.visited_count > package_limit {
                push_package_limit_issue(report, pending.package_id, package_limit as u64);
                break;
            }
            pending.report_source = true;
            frontier.push(pending);
        }

        (!frontier.is_empty()).then_some(frontier)
    }

    pub(super) fn enqueue(&mut self, packages: impl IntoIterator<Item = PendingPackage>) {
        self.queue.extend(packages);
    }

    pub(super) fn visited_count(&self) -> usize {
        self.visited_count
    }

    pub(super) fn remaining_fetch_attempts(&self, package_limit: usize) -> usize {
        package_limit
            .saturating_sub(1)
            .saturating_sub(self.fetch_attempt_count)
    }

    pub(super) fn record_fetch_attempts(&mut self, count: usize) {
        self.fetch_attempt_count = self.fetch_attempt_count.saturating_add(count);
    }
}

pub(super) fn pending_from_fetch(
    request: &FetchRequest,
    metadata: FetchMetadata,
) -> PendingPackage {
    PendingPackage {
        package_id: metadata.package_id.clone(),
        source: metadata.source.clone(),
        depth: request.depth,
        fetched: Some(metadata),
        contexts: request.contexts.clone(),
        report_source: true,
    }
}

pub(super) fn limit_fetch_requests(
    requests: Vec<FetchRequest>,
    report: &mut Report,
    visited_packages: usize,
    package_limit: usize,
) -> Vec<FetchRequest> {
    let mut merged = Vec::<FetchRequest>::new();
    for request in requests {
        if let Some(existing) = merged.iter_mut().find(|existing| {
            existing.dependency.id() == request.dependency.id()
                && existing.dependency.requirement == request.dependency.requirement
                && existing.dependency.source_url == request.dependency.source_url
                && existing.dependency.deno_lockfile_snapshot
                    == request.dependency.deno_lockfile_snapshot
                && (!request.dependency.is_local()
                    || existing.declared_from == request.declared_from)
        }) {
            existing.contexts.extend(request.contexts);
            continue;
        }
        merged.push(request);
    }

    let remaining_packages = package_limit.saturating_sub(visited_packages);
    let mut requests = merged;
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

pub(super) fn canonicalize_root(root: &Path) -> Result<PathBuf> {
    fs::canonicalize(root).map_err(|source| Error::Io {
        operation: "canonicalize project root".to_owned(),
        path: root.to_owned(),
        source,
    })
}

pub(super) fn push_batch_package_limit_issue(report: &mut Report, package_id: String, limit: u64) {
    push_issue(
        report,
        Error::LimitExceeded {
            resource: "batch packages".to_owned(),
            limit,
        },
        Some(package_id),
        "batch traversal",
        true,
    );
}

pub(super) fn push_package_limit_issue(report: &mut Report, package_id: String, limit: u64) {
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
