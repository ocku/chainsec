use std::{
    collections::{HashSet, VecDeque},
    fs,
    path::{Path, PathBuf},
};

use futures::{StreamExt, stream};

const MAX_CONCURRENT_FETCHES: usize = 16;

use crate::{
    error::{Error, Result},
    fetcher::Fetcher,
    manifests,
    model::{
        AnalysisPoint, Confidence, EngineLimits, FetchMetadata, FindingType, Language, Location,
        OperationalIssue, PackageReport, PolicySummary, Report, Risk, Rule, SerializableLimits,
    },
    rules::RuleSelector,
    scanner,
};

struct PendingPackage {
    package_id: String,
    source: PathBuf,
    depth: usize,
    fetched: Option<FetchMetadata>,
    npm_context: Option<manifests::NpmLockContext>,
    python_context: Option<manifests::PythonLockContext>,
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

    async fn analyze_with_root(
        &self,
        root: &Path,
        fetched: Option<FetchMetadata>,
    ) -> Result<Report> {
        let root = canonicalize_root(root)?;
        let mut report = Report::new(root.clone(), self.policy.clone());
        let mut queue = VecDeque::from([PendingPackage::root(root, fetched)]);
        let mut visited = HashSet::new();

        while let Some(pending) = queue.pop_front() {
            if !visited.insert(pending.package_id.clone()) {
                continue;
            }

            if visited.len() > self.limits.max_packages {
                push_package_limit_issue(
                    &mut report,
                    pending.package_id,
                    self.limits.max_packages as u64,
                );
                break;
            }

            let (scan, discovery, python_context) =
                self.scan_and_discover(&pending, &mut report).await;
            let scan_counts = record_scan(&mut report, scan);
            record_install_scripts(&mut report, &pending, &discovery.install_scripts);
            record_package(&mut report, &pending, &discovery, scan_counts);

            if pending.depth < self.limits.max_depth {
                let reserved_packages = visited.len().saturating_add(queue.len());
                let remaining_packages = self.limits.max_packages.saturating_sub(reserved_packages);
                self.fetch_dependencies(
                    pending,
                    discovery,
                    python_context,
                    &mut report,
                    &mut queue,
                    remaining_packages,
                )
                .await;
            }
        }

        report.findings.retain(|finding| {
            !self
                .ignored_rule_selectors
                .iter()
                .any(|selector| selector.matches_finding(finding))
        });
        finalize_report(&mut report);
        Ok(report)
    }

    async fn scan_and_discover(
        &self,
        pending: &PendingPackage,
        report: &mut Report,
    ) -> (
        scanner::ScanOutcome,
        manifests::Discovery,
        Option<manifests::PythonLockContext>,
    ) {
        let scan_task = scanner::scan_async(
            pending.source.clone(),
            pending.package_id.clone(),
            self.rules.to_vec(),
            self.limits.clone(),
            if pending.depth == 0 {
                self.ignored_root_paths.clone()
            } else {
                Vec::new()
            },
        );
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

        let scan = scan_result.unwrap_or_else(|error| {
            push_issue(
                report,
                error,
                Some(pending.package_id.clone()),
                "scan",
                false,
            );
            scanner::ScanOutcome::default()
        });
        let (discovery, python_context) = match discovery_result {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                push_issue(
                    report,
                    error,
                    Some(pending.package_id.clone()),
                    "manifest discovery",
                    false,
                );
                empty_discovery()
            }
            Err(error) => {
                push_issue(
                    report,
                    Error::Manifest {
                        path: pending.source.clone(),
                        message: format!("manifest discovery worker failed: {error}"),
                    },
                    Some(pending.package_id.clone()),
                    "manifest discovery",
                    false,
                );
                empty_discovery()
            }
        };

        (scan, discovery, python_context)
    }

    async fn fetch_dependencies(
        &self,
        pending: PendingPackage,
        discovery: manifests::Discovery,
        python_context: Option<manifests::PythonLockContext>,
        report: &mut Report,
        queue: &mut VecDeque<PendingPackage>,
        remaining_packages: usize,
    ) {
        let mut fetchable = self
            .filter_fetchable_dependencies(&pending, &discovery, report)
            .into_iter()
            .filter(|(dependency, _)| {
                !self
                    .ignored_packages
                    .contains(&ignored_package_id(dependency))
            })
            .collect::<Vec<_>>();
        if fetchable.len() > remaining_packages {
            push_package_limit_issue(
                report,
                pending.package_id.clone(),
                self.limits.max_packages as u64,
            );
            fetchable.truncate(remaining_packages);
        }
        let declared_from = pending.source.clone();
        let fetches = stream::iter(fetchable).map(|(dependency, npm_context)| {
            let declared_from = declared_from.clone();
            async move {
                let dependency_id = dependency.id();
                (
                    self.fetcher.fetch(dependency, declared_from).await,
                    dependency_id,
                    npm_context,
                )
            }
        });

        let mut fetches = fetches.buffered(MAX_CONCURRENT_FETCHES);
        while let Some((result, dependency_id, npm_context)) = fetches.next().await {
            match result {
                Ok(metadata) => queue.push_back(PendingPackage {
                    package_id: metadata.package_id.clone(),
                    source: metadata.source.clone(),
                    depth: pending.depth + 1,
                    fetched: Some(metadata),
                    npm_context,
                    python_context: python_context.clone(),
                }),
                Err(error) => push_issue(report, error, Some(dependency_id), "fetch", false),
            }
        }
    }

    fn filter_fetchable_dependencies(
        &self,
        pending: &PendingPackage,
        discovery: &manifests::Discovery,
        report: &mut Report,
    ) -> Vec<(crate::model::Dependency, Option<manifests::NpmLockContext>)> {
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

fn ignored_package_id(dependency: &crate::model::Dependency) -> String {
    let version = dependency
        .resolved_version
        .as_deref()
        .unwrap_or(&dependency.requirement);
    format!("{}:{}@{version}", dependency.ecosystem, dependency.name)
}

fn record_scan(report: &mut Report, scan: scanner::ScanOutcome) -> (u64, u64) {
    report.statistics.source_files += scan.scanned_files;
    report.statistics.source_bytes += scan.scanned_bytes;
    report.findings.extend(scan.findings);

    (scan.scanned_files, scan.scanned_bytes)
}

fn record_install_scripts(
    report: &mut Report,
    pending: &PendingPackage,
    warnings: &[manifests::InstallScriptWarning],
) {
    for warning in warnings {
        let relative_manifest = warning
            .manifest
            .strip_prefix(&pending.source)
            .unwrap_or(&warning.manifest);
        let file = relative_manifest.to_string_lossy();
        let matched_code = warning.scripts.join(", ");
        let location = first_line_location();
        let (rule_id, risk, rationale, remediation) = install_script_details(warning.language);

        report.findings.push(AnalysisPoint {
            id: AnalysisPoint::stable_id(
                rule_id,
                1,
                &pending.package_id,
                &file,
                &location,
                &matched_code,
            ),
            rule_id: rule_id.to_owned(),
            rule_version: 1,
            finding_type: FindingType::InstallScript,
            risk,
            confidence: Confidence::High,
            rationale: rationale.to_owned(),
            remediation: remediation.to_owned(),
            package: pending.package_id.clone(),
            file: relative_manifest.to_owned(),
            location,
            matched_code,
            suppressed: false,
        });
    }
}

fn first_line_location() -> Location {
    Location {
        start_line: 1,
        start_column: 1,
        end_line: 1,
        end_column: 1,
    }
}

fn install_script_details(language: Language) -> (&'static str, Risk, &'static str, &'static str) {
    match language {
        Language::Python => (
            "PY_INSTALL_SCRIPT",
            Risk::Medium,
            "A Python setup script runs during package installation and can execute arbitrary build-time code.",
            "Review setup.py before installation and prefer declarative packaging configuration.",
        ),
        Language::JavaScript | Language::TypeScript => (
            "NPM_INSTALL_SCRIPT",
            Risk::High,
            "An npm lifecycle script runs during package installation and can execute arbitrary commands.",
            "Remove unnecessary lifecycle scripts and review any remaining commands before installation.",
        ),
    }
}

fn record_package(
    report: &mut Report,
    pending: &PendingPackage,
    discovery: &manifests::Discovery,
    (scanned_files, scanned_bytes): (u64, u64),
) {
    let dependencies = discovery
        .dependencies
        .iter()
        .map(|dependency| dependency.id())
        .collect();
    let (source_url, resolved_version, digest, cache_hit) =
        pending
            .fetched
            .as_ref()
            .map_or((None, None, None, false), |metadata| {
                (
                    Some(metadata.source_url.clone()),
                    Some(metadata.resolved_version.clone()),
                    Some(metadata.digest.clone()),
                    metadata.cache_hit,
                )
            });

    if cache_hit {
        report.statistics.cache_hits += 1;
    }

    report.packages.push(PackageReport {
        package_id: pending.package_id.clone(),
        source: pending.source.clone(),
        source_url,
        resolved_version,
        digest,
        depth: pending.depth,
        dependencies,
        scanned_files,
        scanned_bytes,
    });
}

fn finalize_report(report: &mut Report) {
    report
        .packages
        .sort_by(|a, b| a.package_id.cmp(&b.package_id));
    report.findings.sort_by(|a, b| a.id.cmp(&b.id));
    report
        .issues
        .sort_by(|a, b| (&a.code, &a.package, &a.message).cmp(&(&b.code, &b.package, &b.message)));
    report.statistics.packages = report.packages.len() as u64;
    report.statistics.findings = report.findings.len() as u64;
}

fn push_issue(
    report: &mut Report,
    error: Error,
    package: Option<String>,
    operation: &str,
    fatal: bool,
) {
    report.issues.push(OperationalIssue {
        code: error.code().to_owned(),
        message: error.to_string(),
        package,
        operation: operation.to_owned(),
        fatal,
    });
}

#[cfg(test)]
mod tests;
