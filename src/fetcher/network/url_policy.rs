use url::Url;

use crate::{
    error::{Error, Result},
    fetcher::{SourceFetcher, host_is_allowed},
};

use super::super::{policy::is_loopback_host, repository::url_is_within_base};

#[derive(Clone)]
pub(in crate::fetcher) struct RequestProvenance {
    pub(in crate::fetcher) repository_base: Option<Url>,
    pub(in crate::fetcher) insecure_repository_base: Option<Url>,
}

impl SourceFetcher {
    pub(in crate::fetcher) fn check_url_policy(
        &self,
        url: &Url,
        repository_request: bool,
    ) -> Result<()> {
        let provenance = self.request_provenance(url, repository_request);
        self.check_url_with_provenance(url, &provenance)
    }

    pub(in crate::fetcher) fn request_provenance(
        &self,
        url: &Url,
        repository_request: bool,
    ) -> RequestProvenance {
        let repository_base = repository_request
            .then(|| self.policy.repositories.repository_base_for(url))
            .flatten();
        self.request_provenance_from_repository_base(repository_base)
    }

    pub(in crate::fetcher) fn request_provenance_from_repository_base(
        &self,
        repository_base: Option<Url>,
    ) -> RequestProvenance {
        let insecure_repository_base = repository_base
            .as_ref()
            .filter(|base| base.scheme() == "http")
            .cloned();
        RequestProvenance {
            repository_base,
            insecure_repository_base,
        }
    }

    pub(in crate::fetcher) fn check_url_with_provenance(
        &self,
        url: &Url,
        provenance: &RequestProvenance,
    ) -> Result<()> {
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
}
