use std::env;

use reqwest::header::HeaderValue;
use url::Url;

use crate::{Error, Result};

#[derive(Clone)]
pub(super) struct ScopedCredential {
    scope: Url,
    source: CredentialSource,
}

#[derive(Clone)]
enum CredentialSource {
    Bearer(HeaderValue),
    BearerEnvironment(String),
}

fn has_ambiguous_escaped_path_character(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.windows(3).any(|escape| {
        escape[0] == b'%'
            && escape[1].is_ascii_hexdigit()
            && escape[2].is_ascii_hexdigit()
            && matches!(
                (
                    escape[1].to_ascii_lowercase(),
                    escape[2].to_ascii_lowercase()
                ),
                (b'2', b'5') | (b'2', b'e') | (b'2', b'f') | (b'5', b'c')
            )
    })
}

impl ScopedCredential {
    pub(super) fn bearer(scope: Url, token: &str) -> Option<Self> {
        let token = token.trim();
        if token.is_empty() {
            return None;
        }
        Some(Self {
            scope,
            source: CredentialSource::Bearer(
                HeaderValue::from_str(&format!("Bearer {token}")).ok()?,
            ),
        })
    }

    pub(super) fn bearer_environment(scope: Url, variable: String) -> Self {
        Self {
            scope,
            source: CredentialSource::BearerEnvironment(variable),
        }
    }

    fn matches(&self, url: &Url) -> bool {
        // Do not authorize paths whose escaped representation could be decoded and
        // normalized differently by a proxy or origin server.
        !has_ambiguous_escaped_path_character(self.scope.path())
            && !has_ambiguous_escaped_path_character(url.path())
            // `Url::origin` compares the scheme, canonical host, and effective port.
            // DNS resolution is deliberately not part of credential scoping.
            && self.scope.scheme() == "https"
            && url.scheme() == "https"
            && self.scope.origin() == url.origin()
            && url
                .path()
                .strip_prefix(self.scope.path())
                .is_some_and(|suffix| {
                    self.scope.path().ends_with('/') || suffix.is_empty() || suffix.starts_with('/')
                })
    }

    fn authorization(&self) -> Result<HeaderValue> {
        match &self.source {
            CredentialSource::Bearer(authorization) => Ok(authorization.clone()),
            CredentialSource::BearerEnvironment(variable) => {
                let token = env::var(variable).map_err(|error| Error::InvalidConfiguration {
                    message: format!(
                        "credential environment variable {variable:?} is unavailable: {error}"
                    ),
                })?;
                Self::bearer(self.scope.clone(), &token)
                    .map(|credential| match credential.source {
                        CredentialSource::Bearer(authorization) => authorization,
                        CredentialSource::BearerEnvironment(_) => unreachable!(),
                    })
                    .ok_or_else(|| Error::InvalidConfiguration {
                        message: format!(
                            "credential environment variable {variable:?} is empty or contains an invalid bearer token"
                        ),
                    })
            }
        }
    }
}

pub(super) fn authorization_for(
    credentials: &[ScopedCredential],
    url: &Url,
) -> Result<Option<HeaderValue>> {
    credentials
        .iter()
        .filter(|credential| credential.matches(url))
        .max_by_key(|credential| credential.scope.path().len())
        .map(ScopedCredential::authorization)
        .transpose()
}

#[cfg(test)]
mod tests;
