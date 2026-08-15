use std::net::{IpAddr, ToSocketAddrs};

use crate::error::{Error, Result};

use super::ArtifactRepositories;

#[derive(Debug, Clone)]
pub struct FetchPolicy {
    pub offline: bool,
    pub allow_unlocked: bool,
    pub allowed_hosts: Vec<String>,
    pub repositories: ArtifactRepositories,
    pub trust_local_input: bool,
    /// Permit plaintext HTTP only for configured loopback repositories.
    pub allow_insecure_http: bool,
}

impl Default for FetchPolicy {
    fn default() -> Self {
        Self {
            offline: true,
            allow_unlocked: false,
            allowed_hosts: Vec::new(),
            repositories: ArtifactRepositories::default(),
            trust_local_input: false,
            allow_insecure_http: false,
        }
    }
}

pub(super) fn is_loopback_host(host: &str, port: u16) -> bool {
    let host = host.trim_matches(['[', ']']);
    if let Ok(address) = host.parse::<IpAddr>() {
        return address.is_loopback();
    }

    host.eq_ignore_ascii_case("localhost")
        && (host, port).to_socket_addrs().is_ok_and(|mut addresses| {
            addresses
                .next()
                .is_some_and(|address| address.ip().is_loopback())
                && addresses.all(|address| address.ip().is_loopback())
        })
}

pub(super) fn host_is_allowed(host: &str, allowed_hosts: &[String]) -> bool {
    allowed_hosts.iter().any(|allowed| {
        allowed == "*"
            || host.eq_ignore_ascii_case(allowed)
            || allowed.strip_prefix("*.").is_some_and(|suffix| {
                let prefix_length = host.len().saturating_sub(suffix.len());
                host.get(..prefix_length)
                    .zip(host.get(prefix_length..))
                    .is_some_and(|(prefix, host_suffix)| {
                        prefix.ends_with('.') && host_suffix.eq_ignore_ascii_case(suffix)
                    })
            })
    })
}

pub(super) fn validate_repository_transport(policy: &FetchPolicy) -> Result<()> {
    for url in policy.repositories.urls() {
        if url.scheme() == "https" {
            continue;
        }
        let host = url.host_str().expect("repository URLs always have a host");
        if !policy.allow_insecure_http {
            return Err(Error::InvalidConfiguration {
                message: format!(
                    "configured repository URL {url} uses insecure HTTP; use HTTPS or explicitly enable allow_insecure_http for a loopback development registry"
                ),
            });
        }
        if !is_loopback_host(host, url.port_or_known_default().unwrap_or(80)) {
            return Err(Error::InvalidConfiguration {
                message: format!(
                    "configured repository URL {url} uses insecure HTTP on non-loopback host {host}; allow_insecure_http is limited to localhost resolving only to loopback addresses and loopback IPs"
                ),
            });
        }
    }
    if policy.allow_insecure_http {
        tracing::warn!(
            "insecure HTTP repository transport is enabled; registry metadata and artifact URLs may be exposed to local network attackers"
        );
    }
    Ok(())
}
