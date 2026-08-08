use url::Url;

use crate::{
    error::{Error, Result},
    model::{Dependency, Ecosystem},
};

use super::{SourceFetcher, host_is_allowed};

impl SourceFetcher {
    fn check_url(&self, url: &Url) -> Result<()> {
        if self.policy.offline {
            return Err(Error::Policy {
                operation: "network fetch".to_owned(),
                message: "offline mode is enabled".to_owned(),
            });
        }
        if !matches!(url.scheme(), "http" | "https") {
            return Err(Error::Policy {
                operation: "network fetch".to_owned(),
                message: format!(
                    "scheme {} is forbidden; only http and https are allowed",
                    url.scheme()
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

    pub(super) async fn download(&self, url: &Url) -> Result<Vec<u8>> {
        self.check_url(url)?;
        let client = self
            .client
            .as_ref()
            .expect("fetcher client is available while downloading");
        let mut request_url = url.clone();
        for redirects in 0..=self.policy.max_redirects {
            self.check_url(&request_url)?;
            let mut request = client.get(request_url.clone());
            if credentials_are_permitted(&request_url)
                && let Some(authorization) =
                    self.policy.repositories.authorization_for(&request_url)
            {
                request = request.header(reqwest::header::AUTHORIZATION, authorization);
            }
            let mut response = request.send().await.map_err(|error| Error::Fetch {
                package: "artifact".to_owned(),
                source_url: request_url.to_string(),
                message: error.to_string(),
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
                        source_url: request_url.to_string(),
                        message: "redirect response has no Location header".to_owned(),
                    })?
                    .to_str()
                    .map_err(|_| Error::Fetch {
                        package: "artifact".to_owned(),
                        source_url: request_url.to_string(),
                        message: "redirect Location header is not valid text".to_owned(),
                    })?;
                request_url = request_url.join(location).map_err(|error| Error::Policy {
                    operation: "network redirect".to_owned(),
                    message: format!("invalid redirect target: {error}"),
                })?;
                self.check_url(&request_url).map_err(|error| match error {
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
                    source_url: request_url.to_string(),
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
                source_url: request_url.to_string(),
                message: source.to_string(),
            })? {
                bytes.extend_from_slice(&chunk);
                if bytes.len() as u64 > self.limits.max_archive_bytes {
                    return Err(Error::LimitExceeded {
                        resource: "download bytes".to_owned(),
                        limit: self.limits.max_archive_bytes,
                    });
                }
            }
            return Ok(bytes);
        }
        unreachable!("redirect loop is bounded")
    }

    pub(super) async fn artifact_url(&self, dependency: &Dependency) -> Result<Url> {
        if dependency.ecosystem == Ecosystem::Python {
            return self.python_artifact_url(dependency).await;
        }
        if dependency.ecosystem == Ecosystem::Deno && dependency.requirement.starts_with("npm:") {
            return self.npm_artifact_url(dependency).await;
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
                .jsr_version_metadata_url(package, version);
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
        Url::parse(raw).map_err(|error| Error::Resolution {
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

fn credentials_are_permitted(url: &Url) -> bool {
    !url.host_str()
        .is_some_and(|host| host.eq_ignore_ascii_case("codeload.github.com"))
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::{credentials_are_permitted, jsr_package_name};

    #[test]
    fn preserves_the_scope_when_parsing_an_unversioned_jsr_package() {
        assert_eq!(jsr_package_name("jsr:@std/fs"), "@std/fs");
        assert_eq!(jsr_package_name("jsr:@std/fs@1.0.0"), "@std/fs");
    }

    #[test]
    fn github_archive_urls_never_receive_repository_credentials() {
        assert!(!credentials_are_permitted(
            &Url::parse("https://codeload.github.com/owner/repository/tar.gz/0123456789012345678901234567890123456789")
                .unwrap()
        ));
        assert!(credentials_are_permitted(
            &Url::parse("https://registry.example.test/npm/package").unwrap()
        ));
    }
}
