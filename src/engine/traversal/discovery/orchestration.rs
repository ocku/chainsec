use std::{collections::BTreeSet, sync::Arc};

use crate::{
    engine::{Engine, reporting::operational_issue},
    error::Error,
    manifests,
    model::OperationalIssue,
    scanner,
};

use super::{super::state::PendingPackage, ScanAndDiscovery};

impl Engine<'_> {
    pub(in crate::engine::traversal) async fn discover_package(
        &self,
        pending: &PendingPackage,
    ) -> (
        manifests::Discovery,
        BTreeSet<manifests::PythonLockContext>,
        Vec<OperationalIssue>,
    ) {
        let discovery_source = pending.source.clone();
        let npm_contexts = pending.contexts.npm.iter().cloned().collect::<Vec<_>>();
        let python_contexts = pending.contexts.python.iter().cloned().collect::<Vec<_>>();
        let package_id = pending.package_id.clone();
        let limits = self.limits.clone();
        let discovery = tokio::task::spawn_blocking(move || {
            manifests::discover_with_contexts_and_limits(
                &discovery_source,
                &npm_contexts,
                &python_contexts,
                &limits,
            )
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

    pub(in crate::engine::traversal) async fn scan_and_discover(
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
        let limits = self.limits.clone();
        let discovery = tokio::task::spawn_blocking(move || {
            manifests::discover_with_contexts_and_limits(
                &discovery_source,
                &npm_contexts,
                &python_contexts,
                &limits,
            )
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
}

fn empty_discovery() -> (manifests::Discovery, BTreeSet<manifests::PythonLockContext>) {
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
