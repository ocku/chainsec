use url::Url;

use crate::{
    error::{Error, Result},
    fetcher::SourceFetcher,
    model::Dependency,
};

use super::{
    metadata::{PyPiMetadata, select_locked_artifact},
    resolution_error,
};

impl SourceFetcher {
    pub(in crate::fetcher) async fn python_artifact_url_with_budget(
        &self,
        dependency: &Dependency,
        budget: &mut crate::fetcher::network::NetworkBudget,
    ) -> Result<Url> {
        if let Some(source_url) = dependency.source_url.as_deref() {
            let url = parse_artifact_url(dependency, source_url)?;
            if dependency.lockfile.is_none() {
                self.require_pypi_artifact_url(dependency, url)
            } else {
                Ok(url)
            }
        } else {
            self.python_artifact_url_from_metadata_with_budget(dependency, budget)
                .await
        }
    }

    pub(in crate::fetcher) async fn python_artifact_url_from_metadata_with_budget(
        &self,
        dependency: &Dependency,
        budget: &mut crate::fetcher::network::NetworkBudget,
    ) -> Result<Url> {
        let version = dependency
            .resolved_version
            .as_deref()
            .ok_or_else(|| resolution_error(dependency, "locked version is missing"))?;
        let api = self
            .policy
            .repositories
            .pypi_release_url(&dependency.name, Some(version))?;
        let metadata = self
            .pypi_metadata_with_budget(dependency, &api, budget)
            .await?;
        let artifact = select_locked_artifact(dependency, &metadata)?;
        let url = artifact
            .url
            .as_deref()
            .ok_or_else(|| resolution_error(dependency, "artifact URL is missing"))?;
        let url = parse_artifact_url(dependency, url)?;
        self.require_pypi_artifact_url(dependency, url)
    }

    pub(super) fn require_pypi_artifact_url(
        &self,
        _dependency: &Dependency,
        url: Url,
    ) -> Result<Url> {
        if !self
            .policy
            .repositories
            .pypi_artifact_url_is_permitted(&url)
        {
            self.check_url_policy(&url, false)?;
        }
        Ok(url)
    }

    pub(super) async fn pypi_metadata_with_budget(
        &self,
        dependency: &Dependency,
        api: &Url,
        budget: &mut crate::fetcher::network::NetworkBudget,
    ) -> Result<PyPiMetadata> {
        serde_json::from_slice(&self.download_with_budget(api, true, budget).await?).map_err(
            |error| Error::Resolution {
                package: dependency.id(),
                message: format!("invalid PyPI response: {error}"),
            },
        )
    }
}

fn parse_artifact_url(dependency: &Dependency, raw_url: &str) -> Result<Url> {
    Url::parse(raw_url).map_err(|error| resolution_error(dependency, error.to_string()))
}
