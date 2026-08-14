use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

use crate::fetcher::{RemoteVersionSelection, SourceFetcher, network::diagnostic_url};
use crate::{
    error::{Error, Result},
    model::Dependency,
};

use super::selection::{
    jsr_compare_versions, jsr_package_and_requirement, jsr_range_versions,
    jsr_versions_at_or_below, select_jsr_version,
};

#[derive(Debug, Deserialize)]
pub(super) struct JsrVersionMetadata {
    pub(super) manifest: BTreeMap<String, JsrManifestEntry>,
}

#[derive(Debug, Deserialize)]
pub(super) struct JsrManifestEntry {
    pub(super) size: u64,
    pub(super) checksum: String,
}

impl SourceFetcher {
    #[allow(dead_code)]
    pub(in crate::fetcher) async fn resolve_unlocked_jsr(
        &self,
        dependency: &mut Dependency,
    ) -> Result<()> {
        let mut budget = self.network_budget();
        self.resolve_unlocked_jsr_with_budget(dependency, &mut budget)
            .await
    }

    pub(in crate::fetcher) async fn resolve_unlocked_jsr_with_budget(
        &self,
        dependency: &mut Dependency,
        budget: &mut crate::fetcher::network::NetworkBudget,
    ) -> Result<()> {
        let (package, requirement) = jsr_package_and_requirement(dependency)?;
        let package = package.to_owned();
        let requirement = requirement.to_owned();
        let metadata = self
            .jsr_package_metadata_with_budget(dependency, &package, budget)
            .await?;
        let version = select_jsr_version(dependency, &requirement, &metadata)?;
        self.pin_jsr_version_with_budget(dependency, &package, version, budget)
            .await
    }

    #[allow(dead_code)]
    pub(in crate::fetcher) async fn resolve_jsr_version_selection(
        &self,
        dependency: Dependency,
        selection: RemoteVersionSelection,
    ) -> Result<Vec<Dependency>> {
        let mut budget = self.network_budget();
        self.resolve_jsr_version_selection_with_budget(dependency, selection, &mut budget)
            .await
    }

    pub(in crate::fetcher) async fn resolve_jsr_version_selection_with_budget(
        &self,
        dependency: Dependency,
        selection: RemoteVersionSelection,
        budget: &mut crate::fetcher::network::NetworkBudget,
    ) -> Result<Vec<Dependency>> {
        let (package, requirement) = jsr_package_and_requirement(&dependency)?;
        let package = package.to_owned();
        let metadata = self
            .jsr_package_metadata_with_budget(&dependency, &package, budget)
            .await?;
        match selection {
            RemoteVersionSelection::Last(count) => {
                let selected = select_jsr_version(&dependency, requirement, &metadata)?;
                let versions = jsr_versions_at_or_below(&dependency, &selected, &metadata)?;
                let mut resolved = Vec::new();
                let mut candidates_checked = 0;

                for version in versions {
                    candidates_checked += 1;
                    self.enforce_remote_version_candidate_limit(candidates_checked)?;
                    let mut candidate = dependency.clone();
                    match self
                        .pin_jsr_version_with_budget(&mut candidate, &package, version, budget)
                        .await
                    {
                        Ok(()) => {
                            resolved.push(candidate);
                            self.enforce_remote_version_limit(resolved.len())?;
                            if resolved.len() == count {
                                break;
                            }
                        }
                        Err(error) if historical_jsr_version_unavailable(&error) => {}
                        Err(error) => return Err(error),
                    }
                }
                Ok(resolved)
            }
            RemoteVersionSelection::Compare { from, to } => {
                let versions = jsr_compare_versions(&dependency, &from, &to, &metadata)?;
                let mut resolved = Vec::with_capacity(versions.len());
                for (index, version) in versions.into_iter().enumerate() {
                    self.enforce_remote_version_candidate_limit(index + 1)?;
                    let endpoint = if version == to { "TO" } else { "FROM" };
                    let mut candidate = dependency.clone();
                    self.pin_jsr_version_with_budget(
                        &mut candidate,
                        &package,
                        version.clone(),
                        budget,
                    )
                    .await
                    .map_err(|error| jsr_endpoint_error(&dependency, endpoint, &version, error))?;
                    resolved.push(candidate);
                    self.enforce_remote_version_limit(resolved.len())?;
                }
                Ok(resolved)
            }
            RemoteVersionSelection::Range { from, to } => {
                let versions = jsr_range_versions(&dependency, &from, &to, &metadata)?;
                let mut resolved = Vec::with_capacity(versions.len());
                for (index, version) in versions.into_iter().enumerate() {
                    self.enforce_remote_version_candidate_limit(index + 1)?;
                    let mut candidate = dependency.clone();
                    match self
                        .pin_jsr_version_with_budget(
                            &mut candidate,
                            &package,
                            version.clone(),
                            budget,
                        )
                        .await
                    {
                        Ok(()) => {
                            resolved.push(candidate);
                            self.enforce_remote_version_limit(resolved.len())?;
                        }
                        Err(error) if version == from => {
                            return Err(jsr_endpoint_error(&dependency, "FROM", &version, error));
                        }
                        Err(error) if version == to => {
                            return Err(jsr_endpoint_error(&dependency, "TO", &version, error));
                        }
                        Err(error) if historical_jsr_version_unavailable(&error) => {}
                        Err(error) => return Err(error),
                    }
                }
                Ok(resolved)
            }
        }
    }

    #[allow(dead_code)]
    async fn jsr_package_metadata(
        &self,
        dependency: &Dependency,
        package: &str,
    ) -> Result<JsonValue> {
        let mut budget = self.network_budget();
        self.jsr_package_metadata_with_budget(dependency, package, &mut budget)
            .await
    }

    async fn jsr_package_metadata_with_budget(
        &self,
        dependency: &Dependency,
        package: &str,
        budget: &mut crate::fetcher::network::NetworkBudget,
    ) -> Result<JsonValue> {
        let metadata_url = self.policy.repositories.jsr_package_metadata_url(package)?;
        serde_json::from_slice(
            &self
                .download_with_budget(&metadata_url, true, budget)
                .await?,
        )
        .map_err(|error| Error::Resolution {
            package: dependency.id(),
            message: format!("invalid JSR registry response: {error}"),
        })
    }

    #[allow(dead_code)]
    pub(super) async fn pin_jsr_version(
        &self,
        dependency: &mut Dependency,
        package: &str,
        version: String,
    ) -> Result<()> {
        let mut budget = self.network_budget();
        self.pin_jsr_version_with_budget(dependency, package, version, &mut budget)
            .await
    }

    async fn pin_jsr_version_with_budget(
        &self,
        dependency: &mut Dependency,
        package: &str,
        version: String,
        budget: &mut crate::fetcher::network::NetworkBudget,
    ) -> Result<()> {
        let version_metadata_url = self
            .policy
            .repositories
            .jsr_version_metadata_url(package, &version)?;
        let (version_metadata, effective_metadata_url) = self
            .download_with_effective_url_and_budget(&version_metadata_url, true, budget)
            .await?;
        serde_json::from_slice::<JsrVersionMetadata>(&version_metadata).map_err(|error| {
            Error::Resolution {
                package: dependency.id(),
                message: format!(
                    "invalid JSR version metadata: response from {}: {error}",
                    diagnostic_url(&effective_metadata_url)
                ),
            }
        })?;

        dependency.resolved_version = Some(version);
        dependency.source_url = Some(version_metadata_url.to_string());
        dependency.integrity = Some(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(version_metadata))
        ));
        Ok(())
    }
}

fn jsr_endpoint_error(
    dependency: &Dependency,
    endpoint: &str,
    version: &str,
    error: Error,
) -> Error {
    Error::Resolution {
        package: dependency.id(),
        message: format!("JSR {endpoint} endpoint {version} is not pullable: {error}"),
    }
}

fn historical_jsr_version_unavailable(error: &Error) -> bool {
    if let Error::Fetch { message, .. } = error {
        message.starts_with("HTTP 404") || message.starts_with("HTTP 410")
    } else {
        false
    }
}
