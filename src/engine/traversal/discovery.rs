use std::{collections::BTreeSet, sync::Arc};

use crate::{
    error::Error,
    manifests,
    model::{Dependency, Report},
    scanner,
};

use super::{
    super::{Engine, reporting::operational_issue},
    state::{DiscoveryContexts, FetchRequest, PendingPackage},
};

pub(super) struct ScanAndDiscovery {
    pub(super) scan: scanner::ScanOutcome,
    pub(super) discovery: manifests::Discovery,
    pub(super) python_contexts: std::collections::BTreeSet<manifests::PythonLockContext>,
    pub(super) issues: Vec<crate::model::OperationalIssue>,
}

impl Engine<'_> {
    pub(super) async fn discover_package(
        &self,
        pending: &PendingPackage,
    ) -> (
        manifests::Discovery,
        std::collections::BTreeSet<manifests::PythonLockContext>,
        Vec<crate::model::OperationalIssue>,
    ) {
        let discovery_source = pending.source.clone();
        let npm_contexts = pending.contexts.npm.iter().cloned().collect::<Vec<_>>();
        let python_contexts = pending.contexts.python.iter().cloned().collect::<Vec<_>>();
        let package_id = pending.package_id.clone();
        let discovery = tokio::task::spawn_blocking(move || {
            manifests::discover_with_contexts(&discovery_source, &npm_contexts, &python_contexts)
        })
        .await;

        match discovery {
            Ok(outcome) => {
                let issues = outcome
                    .errors
                    .into_iter()
                    .map(|error| {
                        operational_issue(
                            error,
                            Some(package_id.clone()),
                            "manifest discovery",
                            false,
                        )
                    })
                    .collect();
                (outcome.discovery, outcome.python_contexts, issues)
            }
            Err(error) => {
                let issue = operational_issue(
                    Error::Manifest {
                        path: pending.source.clone(),
                        message: format!("manifest discovery worker failed: {error}"),
                    },
                    Some(package_id),
                    "manifest discovery",
                    false,
                );
                let (discovery, python_contexts) = empty_discovery();
                (discovery, python_contexts, vec![issue])
            }
        }
    }

    pub(super) fn fetch_requests_for(
        &self,
        pending: &PendingPackage,
        discovery: &manifests::Discovery,
        python_contexts: std::collections::BTreeSet<manifests::PythonLockContext>,
        report: &mut Report,
    ) -> impl Iterator<Item = FetchRequest> {
        self.filter_fetchable_dependencies(pending, discovery, report)
            .into_iter()
            .filter(|(dependency, _)| {
                !self
                    .ignored_packages
                    .contains(&ignored_package_id(dependency))
            })
            .map(move |(dependency, npm_contexts)| FetchRequest {
                dependency,
                contexts: DiscoveryContexts {
                    npm: npm_contexts,
                    python: python_contexts.clone(),
                },
                declared_from: pending.source.clone(),
                declared_package_id: pending.package_id.clone(),
                depth: pending.depth + 1,
            })
    }

    pub(super) async fn scan_and_discover(
        &self,
        pending: &PendingPackage,
        resources: Arc<scanner::AnalysisResources>,
    ) -> ScanAndDiscovery {
        let scan_task = async {
            if pending.report_source {
                scanner::scan_async(
                    pending.source.clone(),
                    pending.package_id.clone(),
                    resources,
                    self.limits.clone(),
                    if pending.depth == 0 {
                        self.ignored_root_paths.clone()
                    } else {
                        Vec::new()
                    },
                    pending.fetched.is_none(),
                )
                .await
            } else {
                Ok(scanner::ScanOutcome::default())
            }
        };
        let discovery_source = pending.source.clone();
        let npm_contexts = pending.contexts.npm.iter().cloned().collect::<Vec<_>>();
        let python_contexts = pending.contexts.python.iter().cloned().collect::<Vec<_>>();
        let discovery = tokio::task::spawn_blocking(move || {
            manifests::discover_with_contexts(&discovery_source, &npm_contexts, &python_contexts)
        });
        let (scan_result, discovery_result) = tokio::join!(scan_task, discovery);

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
        let (discovery, python_contexts) = match discovery_result {
            Ok(outcome) => {
                issues.extend(outcome.errors.into_iter().map(|error| {
                    operational_issue(
                        error,
                        Some(pending.package_id.clone()),
                        "manifest discovery",
                        false,
                    )
                }));
                (outcome.discovery, outcome.python_contexts)
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
            python_contexts,
            issues,
        }
    }

    fn filter_fetchable_dependencies(
        &self,
        pending: &PendingPackage,
        discovery: &manifests::Discovery,
        report: &mut Report,
    ) -> Vec<(Dependency, BTreeSet<manifests::NpmLockContext>)> {
        discovery
            .dependencies
            .iter()
            .filter_map(|dependency| {
                if self.require_lockfile
                    && !dependency.is_resolved()
                    && !dependency.requires_registry_integrity()
                {
                    super::super::reporting::push_issue(
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
                    discovery
                        .npm_contexts
                        .get(&dependency.id())
                        .cloned()
                        .unwrap_or_default(),
                ))
            })
            .collect()
    }
}

fn empty_discovery() -> (
    manifests::Discovery,
    std::collections::BTreeSet<manifests::PythonLockContext>,
) {
    (
        manifests::Discovery {
            dependencies: Vec::new(),
            lockfiles: Vec::new(),
            install_scripts: Vec::new(),
            npm_contexts: Default::default(),
        },
        Default::default(),
    )
}

fn ignored_package_id(dependency: &Dependency) -> String {
    let version = dependency
        .resolved_version
        .as_deref()
        .unwrap_or(&dependency.requirement);
    format!("{}:{}@{version}", dependency.ecosystem, dependency.name)
}
