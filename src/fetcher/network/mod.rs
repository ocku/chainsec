use url::Url;

use crate::{
    error::{Error, Result},
    model::{Dependency, Ecosystem},
};

use super::repository::url_is_within_base;
use super::{SourceFetcher, host_is_allowed, policy::is_loopback_host};

pub(super) struct NetworkBudget {
    requests: usize,
    deadline: tokio::time::Instant,
}

#[derive(Clone)]
struct RequestProvenance {
    repository_request: bool,
    insecure_repository_base: Option<Url>,
}

impl SourceFetcher {
    pub(super) fn network_budget(&self) -> NetworkBudget {
        NetworkBudget {
            requests: 0,
            deadline: tokio::time::Instant::now() + self.limits.max_acquisition_duration,
        }
    }

    fn request_provenance(&self, url: &Url, repository_request: bool) -> RequestProvenance {
        let insecure_repository_base = repository_request
            .then(|| self.policy.repositories.repository_base_for(url))
            .flatten()
            .filter(|base| base.scheme() == "http");
        RequestProvenance {
            repository_request,
            insecure_repository_base,
        }
    }

    pub(in crate::fetcher) fn check_url_policy(
        &self,
        url: &Url,
        repository_request: bool,
    ) -> Result<()> {
        let provenance = self.request_provenance(url, repository_request);
        self.check_url_with_provenance(url, &provenance)
    }

    fn check_url_with_provenance(&self, url: &Url, provenance: &RequestProvenance) -> Result<()> {
        if !matches!(url.scheme(), "http" | "https") {
            return Err(Error::Policy {
                operation: "network fetch".to_owned(),
                message: format!(
                    "scheme {} is forbidden; only http and https are allowed",
                    url.scheme()
                ),
            });
        }
        if url.scheme() == "http"
            && (!self.policy.allow_insecure_http
                || !provenance
                    .insecure_repository_base
                    .as_ref()
                    .is_some_and(|base| url_is_within_base(base, url))
                || !url.host_str().is_some_and(|host| {
                    is_loopback_host(host, url.port_or_known_default().unwrap_or(80))
                }))
        {
            return Err(Error::Policy {
                operation: "network fetch".to_owned(),
                message: format!(
                    "insecure URL {url} is forbidden; plaintext HTTP is permitted only for configured loopback repository requests when allow_insecure_http is enabled"
                ),
            });
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(Error::Policy {
                operation: "network fetch".to_owned(),
                message: "URL credentials are forbidden".to_owned(),
            });
        }
        let host = url.host_str().ok_or_else(|| Error::Policy {
            operation: "network fetch".to_owned(),
            message: "URL has no host".to_owned(),
        })?;
        if !host_is_allowed(host, &self.policy.allowed_hosts) {
            return Err(Error::Policy {
                operation: "network fetch".to_owned(),
                message: format!("host {host} is not in the allowlist"),
            });
        }
        Ok(())
    }

    /// Downloads a URL, optionally authorizing a request generated from a configured
    /// or default artifact repository. Lockfile-defined URLs must pass `false`.
    #[allow(dead_code)]
    pub(super) async fn download(&self, url: &Url, repository_request: bool) -> Result<Vec<u8>> {
        self.download_with_effective_url(url, repository_request)
            .await
            .map(|(bytes, _)| bytes)
    }

    pub(super) async fn download_with_budget(
        &self,
        url: &Url,
        repository_request: bool,
        budget: &mut NetworkBudget,
    ) -> Result<Vec<u8>> {
        self.download_with_effective_url_and_budget(url, repository_request, budget)
            .await
            .map(|(bytes, _)| bytes)
    }

    #[allow(dead_code)]
    pub(super) async fn download_with_effective_url(
        &self,
        url: &Url,
        repository_request: bool,
    ) -> Result<(Vec<u8>, Url)> {
        let mut budget = self.network_budget();
        self.download_with_effective_url_and_budget(url, repository_request, &mut budget)
            .await
    }

    pub(super) async fn download_with_effective_url_and_budget(
        &self,
        url: &Url,
        repository_request: bool,
        budget: &mut NetworkBudget,
    ) -> Result<(Vec<u8>, Url)> {
        let deadline = budget.deadline;
        match tokio::time::timeout_at(
            deadline,
            self.download_with_provenance(url, repository_request, budget),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(Error::LimitExceeded {
                resource: "package acquisition seconds".to_owned(),
                limit: self.limits.max_acquisition_duration.as_secs(),
            }),
        }
    }

    async fn download_with_provenance(
        &self,
        url: &Url,
        repository_request: bool,
        budget: &mut NetworkBudget,
    ) -> Result<(Vec<u8>, Url)> {
        if self.policy.offline {
            return Err(Error::Policy {
                operation: "network fetch".to_owned(),
                message: "offline mode is enabled".to_owned(),
            });
        }
        let provenance = self.request_provenance(url, repository_request);
        self.check_url_with_provenance(url, &provenance)?;
        let client = self
            .client
            .as_ref()
            .expect("fetcher client is available while downloading");
        let mut request_url = url.clone();
        for redirects in 0..=self.policy.max_redirects {
            self.check_url_with_provenance(&request_url, &provenance)?;
            budget.requests += 1;
            if budget.requests > self.limits.max_network_requests {
                return Err(Error::LimitExceeded {
                    resource: "network requests per package acquisition".to_owned(),
                    limit: self.limits.max_network_requests as u64,
                });
            }
            let mut request = client.get(request_url.clone());
            let authorization =
                if provenance.repository_request && credentials_are_permitted(&request_url) {
                    self.policy.repositories.authorization_for(&request_url)?
                } else {
                    None
                };
            if let Some(authorization) = authorization {
                request = request.header(reqwest::header::AUTHORIZATION, authorization);
            }
            let mut response = request.send().await.map_err(|error| Error::Fetch {
                package: "artifact".to_owned(),
                source_url: diagnostic_url(&request_url),
                message: error.without_url().to_string(),
            })?;
            if response.status().is_redirection() {
                if redirects == self.policy.max_redirects {
                    return Err(Error::Policy {
                        operation: "network redirect".to_owned(),
                        message: "redirect limit exceeded".to_owned(),
                    });
                }
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .ok_or_else(|| Error::Fetch {
                        package: "artifact".to_owned(),
                        source_url: diagnostic_url(&request_url),
                        message: "redirect response has no Location header".to_owned(),
                    })?
                    .to_str()
                    .map_err(|_| Error::Fetch {
                        package: "artifact".to_owned(),
                        source_url: diagnostic_url(&request_url),
                        message: "redirect Location header is not valid text".to_owned(),
                    })?;
                request_url = request_url.join(location).map_err(|error| Error::Policy {
                    operation: "network redirect".to_owned(),
                    message: format!("invalid redirect target: {error}"),
                })?;
                self.check_url_with_provenance(&request_url, &provenance)
                    .map_err(|error| match error {
                        Error::Policy { message, .. } => Error::Policy {
                            operation: "network redirect".to_owned(),
                            message,
                        },
                        error => error,
                    })?;
                continue;
            }
            if !response.status().is_success() {
                return Err(Error::Fetch {
                    package: "artifact".to_owned(),
                    source_url: diagnostic_url(&request_url),
                    message: format!("HTTP {}", response.status()),
                });
            }
            if let Some(length) = response.content_length()
                && length > self.limits.max_archive_bytes
            {
                return Err(Error::LimitExceeded {
                    resource: "download bytes".to_owned(),
                    limit: self.limits.max_archive_bytes,
                });
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|source| Error::Fetch {
                package: "artifact".to_owned(),
                source_url: diagnostic_url(&request_url),
                message: source.without_url().to_string(),
            })? {
                bytes.extend_from_slice(&chunk);
                if bytes.len() as u64 > self.limits.max_archive_bytes {
                    return Err(Error::LimitExceeded {
                        resource: "download bytes".to_owned(),
                        limit: self.limits.max_archive_bytes,
                    });
                }
            }
            return Ok((bytes, request_url));
        }
        unreachable!("redirect loop is bounded")
    }

    #[cfg(test)]
    pub(super) async fn artifact_url(&self, dependency: &Dependency) -> Result<Url> {
        Ok(self.artifact_request(dependency).await?.0)
    }

    #[allow(dead_code)]
    pub(super) async fn artifact_request(&self, dependency: &Dependency) -> Result<(Url, bool)> {
        let mut budget = self.network_budget();
        self.artifact_request_with_budget(dependency, &mut budget)
            .await
    }

    pub(super) async fn artifact_request_with_budget(
        &self,
        dependency: &Dependency,
        budget: &mut NetworkBudget,
    ) -> Result<(Url, bool)> {
        if let Some(url) = dependency.github_archive_url() {
            return Ok((url, false));
        }
        if dependency.ecosystem == Ecosystem::Python {
            return self
                .python_artifact_url_with_budget(dependency, budget)
                .await
                .map(|url| (url, !artifact_url_is_lockfile_defined(dependency)));
        }
        if dependency.ecosystem == Ecosystem::Deno && dependency.requirement.starts_with("npm:") {
            return self
                .npm_artifact_url_with_budget(dependency, budget)
                .await
                .map(|url| (url, true));
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
                .map(|url| (url, true));
        }
        if dependency.ecosystem == Ecosystem::Npm && !artifact_url_is_lockfile_defined(dependency) {
            return self
                .npm_artifact_url_with_budget(dependency, budget)
                .await
                .map(|url| (url, true));
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
            .map(|url| (url, false))
            .map_err(|error| Error::Resolution {
                package: dependency.id(),
                message: error.to_string(),
            })
    }
}

fn jsr_package_name(requirement: &str) -> &str {
    let specifier = requirement.trim_start_matches("jsr:");
    specifier
        .rsplit_once('@')
        .and_then(|(package, _)| (!package.is_empty()).then_some(package))
        .unwrap_or(specifier)
}

fn artifact_url_is_lockfile_defined(dependency: &Dependency) -> bool {
    matches!(dependency.ecosystem, Ecosystem::Npm | Ecosystem::Python)
        && dependency.source_url.is_some()
        && dependency.lockfile.is_some()
        || dependency.ecosystem == Ecosystem::Deno && dependency.requirement.starts_with("http")
}

fn credentials_are_permitted(url: &Url) -> bool {
    !url.host_str()
        .is_some_and(|host| host.eq_ignore_ascii_case("codeload.github.com"))
}

pub(super) fn diagnostic_url(url: &Url) -> String {
    let mut redacted = url.clone();
    redacted.set_query(None);
    redacted.set_fragment(None);
    redacted.to_string()
}

#[cfg(test)]
mod tests;
