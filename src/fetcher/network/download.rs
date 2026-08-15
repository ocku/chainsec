use url::Url;

use crate::{
    error::{Error, Result},
    fetcher::SourceFetcher,
};

use super::{super::repository::url_is_within_base, url_policy::RequestProvenance};

pub(in crate::fetcher) use crate::fetcher::budget::AcquisitionBudget as NetworkBudget;

impl SourceFetcher {
    pub(in crate::fetcher) fn network_budget(&self) -> NetworkBudget {
        NetworkBudget::new(
            self.limits.max_acquisition_duration,
            self.limits
                .max_archive_size
                .saturating_add(self.limits.max_extracted_size),
        )
    }

    #[cfg(test)]
    pub(in crate::fetcher) async fn download(
        &self,
        url: &Url,
        repository_request: bool,
    ) -> Result<Vec<u8>> {
        let mut budget = self.network_budget();
        self.download_with_budget(url, repository_request, &mut budget)
            .await
    }

    pub(in crate::fetcher) async fn download_with_budget(
        &self,
        url: &Url,
        repository_request: bool,
        budget: &mut NetworkBudget,
    ) -> Result<Vec<u8>> {
        self.download_with_effective_url_and_budget(url, repository_request, budget)
            .await
            .map(|(bytes, _)| bytes)
    }

    /// Downloads an artifact identified by repository metadata. Credentials may
    /// only be used while the request remains within that metadata repository.
    pub(in crate::fetcher) async fn download_with_budget_from_repository(
        &self,
        url: &Url,
        repository_base: &Url,
        budget: &mut NetworkBudget,
    ) -> Result<Vec<u8>> {
        self.download_with_effective_url_and_budget_from_repository(url, repository_base, budget)
            .await
            .map(|(bytes, _)| bytes)
    }

    /// Downloads a request derived from repository metadata while retaining the
    /// metadata repository as the sole authority for credentials.
    pub(in crate::fetcher) async fn download_with_effective_url_and_budget_from_repository(
        &self,
        url: &Url,
        repository_base: &Url,
        budget: &mut NetworkBudget,
    ) -> Result<(Vec<u8>, Url)> {
        let deadline = budget.deadline();
        let provenance =
            self.request_provenance_from_repository_base(Some(repository_base.clone()));
        match tokio::time::timeout_at(
            deadline,
            self.download_with_provenance(url, provenance, "*/*", budget),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(budget.exceeded()),
        }
    }

    pub(in crate::fetcher) async fn download_with_effective_url_and_budget(
        &self,
        url: &Url,
        repository_request: bool,
        budget: &mut NetworkBudget,
    ) -> Result<(Vec<u8>, Url)> {
        self.download_with_accept_and_budget(url, repository_request, "*/*", budget)
            .await
    }

    pub(in crate::fetcher) async fn download_with_accept_and_budget(
        &self,
        url: &Url,
        repository_request: bool,
        accept: &'static str,
        budget: &mut NetworkBudget,
    ) -> Result<(Vec<u8>, Url)> {
        let deadline = budget.deadline();
        match tokio::time::timeout_at(
            deadline,
            self.download_with_provenance(
                url,
                self.request_provenance(url, repository_request),
                accept,
                budget,
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(budget.exceeded()),
        }
    }

    async fn download_with_provenance(
        &self,
        url: &Url,
        provenance: RequestProvenance,
        accept: &'static str,
        budget: &mut NetworkBudget,
    ) -> Result<(Vec<u8>, Url)> {
        if self.policy.offline {
            return Err(Error::Policy {
                operation: "network fetch".to_owned(),
                message: "offline mode is enabled".to_owned(),
            });
        }
        self.check_url_with_provenance(url, &provenance)?;
        let client = self
            .client
            .as_ref()
            .expect("fetcher client is available while downloading");
        let mut request_url = url.clone();
        for redirects in 0..=self.limits.max_redirect_hops {
            self.check_url_with_provenance(&request_url, &provenance)?;
            budget.requests += 1;
            if budget.requests > self.limits.max_network_requests {
                return Err(Error::LimitExceeded {
                    resource: "network requests per package acquisition".to_owned(),
                    limit: self.limits.max_network_requests as u64,
                });
            }
            let mut request = client
                .get(request_url.clone())
                .header(reqwest::header::ACCEPT, accept);
            let authorization = if provenance
                .repository_base
                .as_ref()
                .is_some_and(|base| url_is_within_base(base, &request_url))
            {
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
                if redirects == self.limits.max_redirect_hops {
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
                && length > self.limits.max_archive_size
            {
                return Err(Error::LimitExceeded {
                    resource: "download bytes".to_owned(),
                    limit: self.limits.max_archive_size,
                });
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|source| Error::Fetch {
                package: "artifact".to_owned(),
                source_url: diagnostic_url(&request_url),
                message: source.without_url().to_string(),
            })? {
                append_download_chunk(&mut bytes, &chunk, self.limits.max_archive_size, budget)?;
            }
            return Ok((bytes, request_url));
        }
        Err(Error::Policy {
            operation: "network redirect".to_owned(),
            message: "redirect limit exceeded".to_owned(),
        })
    }
}

fn append_download_chunk(
    bytes: &mut Vec<u8>,
    chunk: &[u8],
    limit: u64,
    budget: &mut NetworkBudget,
) -> Result<()> {
    let resulting_length = u64::try_from(bytes.len())
        .ok()
        .and_then(|length| length.checked_add(u64::try_from(chunk.len()).ok()?));
    if resulting_length.is_none_or(|length| length > limit) {
        return Err(Error::LimitExceeded {
            resource: "download bytes".to_owned(),
            limit,
        });
    }
    budget.account_downloaded_bytes(chunk.len())?;
    bytes.extend_from_slice(chunk);
    Ok(())
}

pub(in crate::fetcher) fn diagnostic_url(url: &Url) -> String {
    let mut redacted = url.clone();
    // Strip userinfo as defense-in-depth; the policy layer already rejects
    // URLs that carry credentials in userinfo, but redact here too so a
    // future regression can't leak them through diagnostics.
    redacted.set_username("").ok();
    redacted.set_password(None).ok();
    redacted.set_query(None);
    redacted.set_fragment(None);
    // Redact path segments that appear to carry embedded credentials. Some
    // registries accept tokens as path components, for example
    // /artifactory/api/npm/<token>/package-name.
    if let Some(redacted_path) = redact_token_like_path_segments(redacted.path()) {
        redacted.set_path(&redacted_path);
    }
    redacted.to_string()
}

/// Returns a copy of `path` with token-like segments replaced by `[redacted]`,
/// or `None` when no segment needs redaction.
fn redact_token_like_path_segments(path: &str) -> Option<String> {
    let mut changed = false;
    let redacted: Vec<&str> = path
        .split('/')
        .map(|segment| {
            if is_token_like_path_segment(segment) {
                changed = true;
                "[redacted]"
            } else {
                segment
            }
        })
        .collect();
    changed.then(|| redacted.join("/"))
}

/// Returns `true` when a URL path segment looks like it may carry an
/// embedded credential (API key, bearer token, or similar secret).
fn is_token_like_path_segment(segment: &str) -> bool {
    // Long hex strings (>= 40 chars). SHA-1 hex is 40 characters; anything
    // this long is essentially never a legitimate package-path component.
    if segment.len() >= 40 && segment.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    // Known GitHub token prefixes (ghp_*, gho_*, ghu_*, ghs_*, ghr_*,
    // github_pat_*).  Require the remainder to be at least 20 characters
    // to avoid false positives on short strings.
    if let Some(rest) = segment
        .strip_prefix("ghp_")
        .or_else(|| segment.strip_prefix("gho_"))
        .or_else(|| segment.strip_prefix("ghu_"))
        .or_else(|| segment.strip_prefix("ghs_"))
        .or_else(|| segment.strip_prefix("ghr_"))
        .or_else(|| segment.strip_prefix("github_pat_"))
    {
        return rest.len() >= 20;
    }
    false
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{NetworkBudget, append_download_chunk};

    #[test]
    fn download_limit_is_checked_before_appending_a_chunk() {
        let mut bytes = b"1234".to_vec();
        let mut budget = NetworkBudget::new(Duration::from_secs(1), 100);

        let error = append_download_chunk(&mut bytes, b"56", 5, &mut budget).unwrap_err();

        assert!(matches!(
            error,
            crate::Error::LimitExceeded { limit: 5, .. }
        ));
        assert_eq!(bytes, b"1234");
    }

    #[test]
    fn acquisition_download_limit_is_shared_across_response_bodies() {
        let mut budget = NetworkBudget::new(Duration::from_secs(1), 5);
        let mut first = Vec::new();
        let mut second = Vec::new();
        append_download_chunk(&mut first, b"abc", 10, &mut budget).unwrap();

        let error = append_download_chunk(&mut second, b"def", 10, &mut budget).unwrap_err();

        assert!(matches!(
            error,
            crate::Error::LimitExceeded { resource, limit: 5 }
                if resource == "download bytes per package acquisition"
        ));
        assert!(second.is_empty());
    }
}
