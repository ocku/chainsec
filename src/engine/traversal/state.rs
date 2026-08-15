use std::{
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
    fs,
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
};

use crate::{
    error::{Error, Result},
    manifests,
    model::{DenoLockfileSnapshot, Dependency, FetchMetadata, Report},
};

use super::super::reporting::push_issue;

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
    identity: FetchIdentity,
}

pub(super) enum AcquisitionDecision {
    Revisited,
    Reserved,
    LimitExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum FetchIdentity {
    Acquisition {
        identity: String,
        deno_lockfile_snapshot: Option<String>,
    },
    Declaration {
        requirement: String,
        source_url: Option<String>,
        deno_lockfile_snapshot: Option<String>,
        declared_from: Option<PathBuf>,
    },
}

#[derive(PartialEq, Eq)]
struct FetchRequestKey {
    package_id: String,
    requirement: String,
    source_url: Option<String>,
    deno_lockfile_snapshot: Option<DenoLockfileSnapshot>,
    declared_from: Option<PathBuf>,
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
    root_fetch: Option<FetchMetadata>,
    visited_authenticated_packages: HashMap<String, FetchMetadata>,
    visited_sources: HashSet<PathBuf>,
    visited_contexts: HashMap<PathBuf, DiscoveryContexts>,
    visited_count: usize,
    acquisition_keys: HashSet<FetchKey>,
    successful_acquisitions: HashMap<FetchKey, FetchMetadata>,
}

impl Hash for FetchRequestKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.package_id.hash(state);
        self.requirement.hash(state);
        self.source_url.hash(state);
        self.deno_lockfile_snapshot
            .as_ref()
            .map(DenoLockfileSnapshot::identity)
            .hash(state);
        self.declared_from.hash(state);
    }
}

impl FetchRequestKey {
    fn new(request: &FetchRequest) -> Self {
        Self {
            package_id: request.dependency.id(),
            requirement: request.dependency.requirement.clone(),
            source_url: request.dependency.source_url.clone(),
            deno_lockfile_snapshot: request.dependency.deno_lockfile_snapshot.clone(),
            declared_from: request
                .dependency
                .is_local()
                .then(|| request.declared_from.clone()),
        }
    }
}

impl FetchKey {
    pub(super) fn new(request: &FetchRequest, prepared: &crate::fetcher::PreparedFetch) -> Self {
        let deno_lockfile_snapshot = request
            .dependency
            .deno_lockfile_snapshot
            .as_ref()
            .map(|snapshot| snapshot.identity().to_owned());
        let identity = match (
            request.dependency.is_local(),
            prepared.acquisition_identity.as_ref(),
        ) {
            (false, Some(identity)) => FetchIdentity::Acquisition {
                identity: identity.clone(),
                deno_lockfile_snapshot,
            },
            _ => FetchIdentity::Declaration {
                requirement: request.dependency.requirement.clone(),
                source_url: request.dependency.source_url.clone(),
                deno_lockfile_snapshot,
                declared_from: request
                    .dependency
                    .is_local()
                    .then(|| request.declared_from.clone()),
            },
        };
        Self {
            package_id: request.dependency.id(),
            identity,
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

    fn authenticated_package_id(&self) -> Option<&str> {
        let package_id = self.resolved_package_id();
        let (_, integrity) = package_id.split_once('#')?;
        let local_unverified = self
            .fetched
            .as_ref()
            .is_some_and(|metadata| metadata.digest == "local-unverified");
        // Unverified IDs identify a declaration, not its bytes, so their fetched
        // source remains part of traversal identity.
        (!local_unverified && integrity != "unverified" && !integrity.starts_with("unverified@"))
            .then_some(package_id)
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
            queue: VecDeque::from([PendingPackage::root(root, fetched.clone())]),
            root_fetch: fetched,
            visited_authenticated_packages: HashMap::new(),
            visited_sources: HashSet::new(),
            visited_contexts: HashMap::new(),
            visited_count: 0,
            acquisition_keys: HashSet::new(),
            successful_acquisitions: HashMap::new(),
        }
    }

    pub(super) fn next_frontier(
        &mut self,
        report: &mut Report,
        package_limit: usize,
    ) -> Option<Vec<PendingPackage>> {
        let depth = self.queue.front()?.depth;
        let mut merged = Vec::<PendingPackage>::new();
        let mut authenticated_package_indices = HashMap::<String, usize>::new();
        let mut source_indices = HashMap::<PathBuf, usize>::new();

        while self
            .queue
            .front()
            .is_some_and(|pending| pending.depth == depth)
        {
            let pending = self.queue.pop_front().expect("frontier entry must exist");
            let package_index = pending
                .authenticated_package_id()
                .and_then(|package_id| authenticated_package_indices.get(package_id).copied());
            let source_index = source_indices.get(pending.source.as_path()).copied();
            let existing_index = match (package_index, source_index) {
                (Some(package_index), Some(source_index)) => Some(package_index.min(source_index)),
                (index, None) | (None, index) => index,
            };

            if let Some(index) = existing_index {
                merged[index].contexts.extend(pending.contexts);
                continue;
            }

            let index = merged.len();
            if let Some(package_id) = pending.authenticated_package_id() {
                authenticated_package_indices.insert(package_id.to_owned(), index);
            }
            source_indices.insert(pending.source.clone(), index);
            merged.push(pending);
        }

        let mut frontier = Vec::new();
        for mut pending in merged {
            let visited = pending
                .authenticated_package_id()
                .is_some_and(|package_id| {
                    self.visited_authenticated_packages.contains_key(package_id)
                })
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

            if let (Some(package_id), Some(metadata)) = (
                pending.authenticated_package_id().map(str::to_owned),
                pending.fetched.clone(),
            ) {
                self.visited_authenticated_packages
                    .insert(package_id, metadata);
            }
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

    pub(super) fn reserve_acquisition(
        &mut self,
        key: FetchKey,
        package_limit: usize,
    ) -> AcquisitionDecision {
        if self.acquisition_keys.contains(&key) {
            return AcquisitionDecision::Revisited;
        }
        if self.acquisition_keys.len() >= package_limit.saturating_sub(1) {
            return AcquisitionDecision::LimitExceeded;
        }

        self.acquisition_keys.insert(key);
        AcquisitionDecision::Reserved
    }

    pub(super) fn record_successful_acquisition(&mut self, key: FetchKey, metadata: FetchMetadata) {
        self.successful_acquisitions.insert(key, metadata);
    }

    pub(super) fn pending_for_revisited_acquisition(
        &self,
        key: &FetchKey,
        request: &FetchRequest,
    ) -> Option<PendingPackage> {
        self.successful_acquisitions
            .get(key)
            .or_else(|| {
                self.root_fetch.as_ref().filter(|metadata| {
                    metadata.package_id == key.package_id
                        && request.dependency.source_url.as_deref()
                            == Some(metadata.source_url.as_str())
                })
            })
            .cloned()
            .map(|metadata| pending_from_fetch(request, metadata))
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

pub(super) fn merge_fetch_requests(requests: Vec<FetchRequest>) -> Vec<FetchRequest> {
    let mut merged = Vec::<FetchRequest>::with_capacity(requests.len());
    let mut request_indices = HashMap::<FetchRequestKey, usize>::with_capacity(requests.len());
    for request in requests {
        let key = FetchRequestKey::new(&request);
        if let Some(index) = request_indices.get(&key).copied() {
            merged[index].contexts.extend(request.contexts);
            continue;
        }

        request_indices.insert(key, merged.len());
        merged.push(request);
    }

    merged
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
