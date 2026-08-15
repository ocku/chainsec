use url::Url;

use crate::{
    error::{Error, Result},
    fetcher::SourceFetcher,
    model::{Dependency, Ecosystem},
};

use super::NetworkBudget;

impl SourceFetcher {
    #[cfg(test)]
    pub(in crate::fetcher) async fn artifact_url(&self, dependency: &Dependency) -> Result<Url> {
        let mut budget = self.network_budget();
        Ok(self
            .artifact_request_with_budget(dependency, &mut budget)
            .await?
            .0)
    }

    pub(in crate::fetcher) async fn artifact_request_with_budget(
        &self,
        dependency: &Dependency,
        budget: &mut NetworkBudget,
    ) -> Result<(Url, bool, Option<Url>)> {
        if let Some(url) = dependency.github_archive_url() {
            return Ok((url, false, None));
        }
        if dependency.ecosystem == Ecosystem::Python {
            return self
                .python_artifact_url_with_budget(dependency, budget)
                .await
                .map(|url| (url, !artifact_url_is_lockfile_defined(dependency), None));
        }
        if dependency.ecosystem == Ecosystem::Deno && dependency.requirement.starts_with("npm:") {
            return self
                .npm_artifact_request_with_budget(dependency, budget)
                .await
                .map(|(url, repository_base)| (url, true, Some(repository_base)));
        }
        if dependency.ecosystem == Ecosystem::Deno && dependency.requirement.starts_with("jsr:") {
            let version =
                dependency
                    .resolved_version
                    .as_deref()
                    .ok_or_else(|| Error::Resolution {
                        package: dependency.id(),
                        message: "JSR dependency has no locked version".to_owned(),
                    })?;
            let package = jsr_package_name(&dependency.requirement);
            return self
                .policy
                .repositories
                .jsr_version_metadata_url(package, version)
                .map(|url| (url, true, None));
        }
        if dependency.ecosystem == Ecosystem::Npm && !artifact_url_is_lockfile_defined(dependency) {
            return self
                .npm_artifact_request_with_budget(dependency, budget)
                .await
                .map(|(url, repository_base)| (url, true, Some(repository_base)));
        }
        let raw = dependency
            .source_url
            .as_deref()
            .or_else(|| {
                (dependency.ecosystem == Ecosystem::Deno
                    && dependency.requirement.starts_with("http"))
                .then_some(dependency.requirement.as_str())
            })
            .ok_or_else(|| Error::Resolution {
                package: dependency.id(),
                message: "lockfile did not provide an artifact URL".to_owned(),
            })?;
        Url::parse(raw)
            .map(|url| (url, false, None))
            .map_err(|error| Error::Resolution {
                package: dependency.id(),
                message: error.to_string(),
            })
    }
}

pub(in crate::fetcher) fn jsr_package_name(requirement: &str) -> &str {
    let specifier = requirement.trim_start_matches("jsr:");
    let Some((scope, remainder)) = specifier.split_once('/') else {
        return specifier;
    };
    let name_end = remainder.find(['@', '/']).unwrap_or(remainder.len());
    &specifier[..scope.len() + 1 + name_end]
}

pub(in crate::fetcher) fn artifact_url_is_lockfile_defined(dependency: &Dependency) -> bool {
    matches!(dependency.ecosystem, Ecosystem::Npm | Ecosystem::Python)
        && dependency.source_url.is_some()
        && dependency.lockfile.is_some()
        || dependency.ecosystem == Ecosystem::Deno && dependency.requirement.starts_with("http")
}
