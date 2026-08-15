use serde_json::Value as JsonValue;
use url::Url;

use crate::{
    error::{Error, Result},
    fetcher::SourceFetcher,
    model::{Dependency, Ecosystem},
};

use super::resolution::npm_package_and_requirement;

impl SourceFetcher {
    pub(in crate::fetcher) async fn npm_artifact_request_with_budget(
        &self,
        dependency: &Dependency,
        budget: &mut crate::fetcher::network::NetworkBudget,
    ) -> Result<(Url, Url)> {
        // Standard npm lockfiles pin the artifact URL. Honor that binding instead
        // of re-resolving it through registry metadata. Deno `npm:` entries use
        // their configured registry metadata endpoint by design.
        if dependency.ecosystem == Ecosystem::Npm
            && let Some(url) = locked_npm_artifact_url(dependency)?
        {
            return Ok((
                url,
                self.policy.repositories.npm_metadata_base_url().clone(),
            ));
        }

        let version = dependency
            .resolved_version
            .as_deref()
            .ok_or_else(|| Error::Resolution {
                package: dependency.id(),
                message: "npm dependency has no locked version".to_owned(),
            })?;
        let (package, _) = npm_package_and_requirement(dependency);
        let metadata = self
            .npm_metadata_with_budget(dependency, &package, budget)
            .await?;
        Ok((
            npm_tarball_url(dependency, version, &metadata)?,
            self.policy.repositories.npm_metadata_base_url().clone(),
        ))
    }
}

pub(super) fn locked_npm_artifact_url(dependency: &Dependency) -> Result<Option<Url>> {
    dependency
        .source_url
        .as_deref()
        .map(|url| {
            Url::parse(url).map_err(|error| Error::Resolution {
                package: dependency.id(),
                message: format!("invalid locked npm tarball URL: {error}"),
            })
        })
        .transpose()
}

fn npm_tarball_url(dependency: &Dependency, version: &str, metadata: &JsonValue) -> Result<Url> {
    let tarball = metadata
        .get("versions")
        .and_then(|versions| versions.get(version))
        .and_then(|release| release.get("dist"))
        .and_then(|dist| dist.get("tarball"))
        .and_then(JsonValue::as_str)
        .ok_or_else(|| Error::Resolution {
            package: dependency.id(),
            message: format!("npm registry has no tarball URL for locked release {version}"),
        })?;
    Url::parse(tarball).map_err(|error| Error::Resolution {
        package: dependency.id(),
        message: format!("invalid npm tarball URL: {error}"),
    })
}
