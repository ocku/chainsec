use std::str::FromStr;

use pep440_rs::{Version, VersionSpecifiers};

use crate::{
    error::Result,
    fetcher::{RemoteVersionSelection, SourceFetcher},
    model::Dependency,
};

use super::{
    metadata::{PyPiMetadata, pin_python_release, select_source_distribution},
    resolution_error,
    versions::python_compare_versions,
};

impl SourceFetcher {
    #[allow(dead_code)]
    pub(in crate::fetcher) async fn resolve_unlocked_python(
        &self,
        dependency: &mut Dependency,
    ) -> Result<()> {
        let mut budget = self.network_budget();
        self.resolve_unlocked_python_with_budget(dependency, &mut budget)
            .await
    }

    pub(in crate::fetcher) async fn resolve_unlocked_python_with_budget(
        &self,
        dependency: &mut Dependency,
        budget: &mut crate::fetcher::network::NetworkBudget,
    ) -> Result<()> {
        let api = self
            .policy
            .repositories
            .pypi_release_url(&dependency.name, None)?;
        let metadata = self
            .pypi_metadata_with_budget(dependency, &api, budget)
            .await?;
        resolve_python_release(dependency, &metadata)
    }

    #[allow(dead_code)]
    pub(in crate::fetcher) async fn resolve_python_version_selection(
        &self,
        dependency: Dependency,
        selection: RemoteVersionSelection,
    ) -> Result<Vec<Dependency>> {
        let mut budget = self.network_budget();
        self.resolve_python_version_selection_with_budget(dependency, selection, &mut budget)
            .await
    }

    pub(in crate::fetcher) async fn resolve_python_version_selection_with_budget(
        &self,
        dependency: Dependency,
        selection: RemoteVersionSelection,
        budget: &mut crate::fetcher::network::NetworkBudget,
    ) -> Result<Vec<Dependency>> {
        let api = self
            .policy
            .repositories
            .pypi_release_url(&dependency.name, None)?;
        let metadata = self
            .pypi_metadata_with_budget(&dependency, &api, budget)
            .await?;
        match selection {
            RemoteVersionSelection::Last(count) => {
                let mut selected = dependency;
                resolve_python_release(&mut selected, &metadata)?;
                self.python_versions_at_or_below(selected, count, &metadata)
            }
            RemoteVersionSelection::Compare { from, to } => {
                python_compare_versions(&dependency, &from, &to, &metadata)
            }
            RemoteVersionSelection::Range { from, to } => {
                self.python_range_versions(&dependency, &from, &to, &metadata)
            }
        }
    }
}

pub(super) fn resolve_python_release(
    dependency: &mut Dependency,
    metadata: &PyPiMetadata,
) -> Result<()> {
    let specifier = python_specifier(dependency)?;
    let releases = metadata
        .releases
        .as_ref()
        .ok_or_else(|| resolution_error(dependency, "PyPI response has no releases"))?;
    let candidates = releases
        .iter()
        .filter_map(|(raw_version, artifacts)| {
            let version = Version::from_str(raw_version).ok()?;
            if !specifier
                .as_ref()
                .is_none_or(|specifier| specifier.contains(&version))
            {
                return None;
            }
            select_source_distribution(artifacts).map(|artifact| (version, raw_version, artifact))
        })
        .collect::<Vec<_>>();
    let allow_prereleases = python_prereleases_explicitly_allowed(specifier.as_ref());
    let has_final_release = candidates
        .iter()
        .any(|(version, ..)| !version.any_prerelease());
    let selected = candidates
        .into_iter()
        .filter(|(version, ..)| {
            allow_prereleases || !has_final_release || !version.any_prerelease()
        })
        .max_by(|(left, ..), (right, ..)| left.cmp(right))
        .ok_or_else(|| {
            resolution_error(
                dependency,
                format!(
                    "PyPI has no non-yanked source distribution with SHA-256 integrity satisfying {}",
                    dependency.requirement
                ),
            )
        })?;

    let (_, version, artifact) = selected;
    pin_python_release(dependency, version, artifact);
    Ok(())
}

fn python_specifier(dependency: &Dependency) -> Result<Option<VersionSpecifiers>> {
    let requirement = dependency
        .requirement
        .split(';')
        .next()
        .unwrap_or(&dependency.requirement)
        .trim();
    let mut raw = requirement
        .strip_prefix(&dependency.name)
        .unwrap_or(requirement)
        .trim();
    if raw.starts_with('[')
        && let Some(end) = raw.find(']')
    {
        raw = raw[end + 1..].trim();
    }
    if raw.is_empty() || raw == "*" {
        return Ok(None);
    }

    VersionSpecifiers::from_str(raw).map(Some).map_err(|error| {
        resolution_error(
            dependency,
            format!("unsupported Python version requirement {raw:?}: {error}"),
        )
    })
}

fn python_prereleases_explicitly_allowed(specifier: Option<&VersionSpecifiers>) -> bool {
    specifier.is_some_and(|specifier| specifier.iter().any(|item| item.any_prerelease()))
}
