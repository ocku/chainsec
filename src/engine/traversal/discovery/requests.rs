use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use crate::{
    engine::{Engine, reporting::push_issue},
    error::Error,
    manifests,
    model::{Dependency, Report},
};

use super::super::state::{DiscoveryContexts, FetchRequest, PendingPackage};

impl Engine<'_> {
    pub(in crate::engine::traversal) fn fetch_requests_for(
        &self,
        pending: &PendingPackage,
        discovery: &manifests::Discovery,
        python_contexts: BTreeSet<manifests::PythonLockContext>,
        report: &mut Report,
    ) -> impl Iterator<Item = FetchRequest> {
        self.filter_fetchable_dependencies(pending, discovery, report)
            .into_iter()
            .filter(|(dependency, _, _)| {
                !self
                    .ignored_packages
                    .contains(&ignored_package_id(dependency))
            })
            .map(
                move |(dependency, npm_contexts, declared_from)| FetchRequest {
                    dependency,
                    contexts: DiscoveryContexts {
                        npm: npm_contexts,
                        python: python_contexts.clone(),
                    },
                    declared_from,
                    declared_package_id: pending.package_id.clone(),
                    depth: pending.depth + 1,
                },
            )
    }

    fn filter_fetchable_dependencies(
        &self,
        pending: &PendingPackage,
        discovery: &manifests::Discovery,
        report: &mut Report,
    ) -> Vec<(Dependency, BTreeSet<manifests::NpmLockContext>, PathBuf)> {
        discovery
            .dependencies
            .iter()
            .flat_map(|dependency| {
                if self.require_lockfile
                    && !dependency.is_resolved()
                    && !dependency.requires_registry_integrity()
                {
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
                    return Vec::new();
                }

                let mut npm_contexts = discovery
                    .npm_contexts
                    .get(&dependency.id())
                    .cloned()
                    .unwrap_or_default();
                npm_contexts.extend(
                    discovery
                        .npm_contexts
                        .get(&dependency.npm_declaration_key())
                        .into_iter()
                        .flatten()
                        .cloned(),
                );
                let declaration_directories = npm_contexts
                    .iter()
                    .filter_map(manifests::NpmLockContext::declaration_directory)
                    .map(Path::to_path_buf)
                    .collect::<BTreeSet<_>>();
                npm_contexts.retain(|context| context.declaration_directory().is_none());

                let declared_from = if dependency.is_local() && !declaration_directories.is_empty()
                {
                    declaration_directories
                } else {
                    BTreeSet::from([pending.source.clone()])
                };
                declared_from
                    .into_iter()
                    .map(|declared_from| (dependency.clone(), npm_contexts.clone(), declared_from))
                    .collect()
            })
            .collect()
    }
}

fn ignored_package_id(dependency: &Dependency) -> String {
    let version = dependency
        .resolved_version
        .as_deref()
        .unwrap_or(&dependency.requirement);
    format!("{}:{}@{version}", dependency.ecosystem, dependency.name)
}
