use std::fmt;

use reqwest::header::HeaderValue;
use url::Url;

use crate::error::{Error, Result};

use super::credentials::{ScopedCredential, authorization_for};

/// Package repository endpoints used to resolve metadata and locate artifacts.
///
/// Each URL is a base path. Package names and versions are appended as escaped
/// path segments, so bases may point at a public registry or a repository
/// manager endpoint.
#[derive(Clone)]
pub struct ArtifactRepositories {
    npm_metadata_base_url: Url,
    pypi_metadata_base_url: Url,
    pypi_artifact_base_url: Url,
    jsr_metadata_base_url: Url,
    credentials: Vec<ScopedCredential>,
}

impl fmt::Debug for ArtifactRepositories {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactRepositories")
            .field("npm_metadata_base_url", &self.npm_metadata_base_url)
            .field("pypi_metadata_base_url", &self.pypi_metadata_base_url)
            .field("pypi_artifact_base_url", &self.pypi_artifact_base_url)
            .field("jsr_metadata_base_url", &self.jsr_metadata_base_url)
            .field("credential_count", &self.credentials.len())
            .finish()
    }
}

impl Default for ArtifactRepositories {
    fn default() -> Self {
        Self::new(
            "https://registry.npmjs.org",
            "https://pypi.org/pypi",
            "https://jsr.io",
        )
        .and_then(|repositories| {
            repositories.with_pypi_artifact_base_url("https://files.pythonhosted.org")
        })
        .expect("built-in repository URLs are valid")
    }
}

impl ArtifactRepositories {
    pub fn new(
        npm_metadata_base_url: impl AsRef<str>,
        pypi_metadata_base_url: impl AsRef<str>,
        jsr_metadata_base_url: impl AsRef<str>,
    ) -> Result<Self> {
        let pypi_metadata_base_url =
            parse_base_url("PyPI metadata", pypi_metadata_base_url.as_ref())?;
        Ok(Self {
            npm_metadata_base_url: parse_base_url("npm metadata", npm_metadata_base_url.as_ref())?,
            pypi_artifact_base_url: pypi_metadata_base_url.clone(),
            pypi_metadata_base_url,
            jsr_metadata_base_url: parse_base_url("JSR metadata", jsr_metadata_base_url.as_ref())?,
            credentials: Vec::new(),
        })
    }

    pub fn with_npm_metadata_base_url(mut self, value: impl AsRef<str>) -> Result<Self> {
        self.npm_metadata_base_url = parse_base_url("npm metadata", value.as_ref())?;
        Ok(self)
    }

    pub fn with_pypi_metadata_base_url(mut self, value: impl AsRef<str>) -> Result<Self> {
        let base_url = parse_base_url("PyPI metadata", value.as_ref())?;
        self.pypi_artifact_base_url = base_url.clone();
        self.pypi_metadata_base_url = base_url;
        Ok(self)
    }

    pub fn with_pypi_artifact_base_url(mut self, value: impl AsRef<str>) -> Result<Self> {
        self.pypi_artifact_base_url = parse_base_url("PyPI artifact", value.as_ref())?;
        Ok(self)
    }

    pub fn pypi_artifact_base_url(&self) -> &Url {
        &self.pypi_artifact_base_url
    }

    pub(super) fn pypi_artifact_url_is_permitted(&self, url: &Url) -> bool {
        url_is_within_base(&self.pypi_artifact_base_url, url)
    }

    pub(super) fn repository_base_for(&self, url: &Url) -> Option<Url> {
        self.urls()
            .into_iter()
            .filter(|base| url_is_within_base(base, url))
            .max_by_key(|base| base.path().len())
            .cloned()
    }

    pub(super) fn urls(&self) -> [&Url; 4] {
        [
            &self.npm_metadata_base_url,
            &self.pypi_metadata_base_url,
            &self.pypi_artifact_base_url,
            &self.jsr_metadata_base_url,
        ]
    }

    pub fn with_jsr_metadata_base_url(mut self, value: impl AsRef<str>) -> Result<Self> {
        self.jsr_metadata_base_url = parse_base_url("JSR metadata", value.as_ref())?;
        Ok(self)
    }

    pub fn npm_metadata_url(&self, package: &str) -> Result<Url> {
        append_path_segments(&self.npm_metadata_base_url, [package])
    }

    pub fn pypi_release_url(&self, package: &str, version: Option<&str>) -> Result<Url> {
        let mut segments = vec![package];
        if let Some(version) = version {
            segments.push(version);
        }
        segments.push("json");
        append_path_segments(&self.pypi_metadata_base_url, segments)
    }

    /// Adds a bearer token for an explicit HTTP(S) URL scope.
    ///
    /// Credentials are re-evaluated for each redirect and are sent only to URLs
    /// within this scheme, host, port, and path scope.
    pub fn with_bearer_token(
        mut self,
        scope: impl AsRef<str>,
        token: impl AsRef<str>,
    ) -> Result<Self> {
        let scope = parse_credential_scope(scope.as_ref())?;
        let credential = ScopedCredential::bearer(scope, token.as_ref()).ok_or_else(|| {
            Error::InvalidConfiguration {
                message: "repository bearer token must be non-empty and valid for an HTTP header"
                    .to_owned(),
            }
        })?;
        self.credentials.push(credential);
        Ok(self)
    }

    /// Adds a bearer token resolved from an environment variable when a request matches `scope`.
    pub fn with_bearer_token_environment(
        mut self,
        scope: impl AsRef<str>,
        variable: impl Into<String>,
    ) -> Result<Self> {
        let scope = parse_credential_scope(scope.as_ref())?;
        self.credentials
            .push(ScopedCredential::bearer_environment(scope, variable.into()));
        Ok(self)
    }

    pub(super) fn authorization_for(&self, url: &Url) -> Result<Option<HeaderValue>> {
        authorization_for(&self.credentials, url)
    }

    pub fn jsr_package_metadata_url(&self, package: &str) -> Result<Url> {
        let (scope, name) = jsr_package_segments(package)?;
        append_path_segments(&self.jsr_metadata_base_url, [scope, name, "meta.json"])
    }

    pub fn jsr_version_metadata_url(&self, package: &str, version: &str) -> Result<Url> {
        let (scope, name) = jsr_package_segments(package)?;
        append_path_segments(
            &self.jsr_metadata_base_url,
            [scope, name, &format!("{version}_meta.json")],
        )
    }
}

fn has_ambiguous_escaped_path_character(path: &str) -> bool {
    path.as_bytes().windows(3).any(|escape| {
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

pub(super) fn url_is_within_base(base: &Url, candidate: &Url) -> bool {
    !has_ambiguous_escaped_path_character(base.path())
        && !has_ambiguous_escaped_path_character(candidate.path())
        && base.scheme() == candidate.scheme()
        && base.host_str() == candidate.host_str()
        && base.port_or_known_default() == candidate.port_or_known_default()
        && path_is_within_base(base, candidate)
}

fn path_is_within_base(base: &Url, candidate: &Url) -> bool {
    let base_segments: Vec<_> = base
        .path_segments()
        .expect("absolute HTTP(S) base URL has path segments")
        .filter(|segment| !segment.is_empty())
        .collect();
    let candidate_segments: Vec<_> = candidate
        .path_segments()
        .expect("absolute HTTP(S) candidate URL has path segments")
        .filter(|segment| !segment.is_empty())
        .collect();

    candidate_segments.starts_with(&base_segments)
}

fn parse_base_url(repository: &str, raw: &str) -> Result<Url> {
    if has_ambiguous_escaped_path_character(raw) {
        return Err(Error::InvalidConfiguration {
            message: format!(
                "{repository} repository URL cannot contain percent-encoded dot, slash, or backslash path octets"
            ),
        });
    }
    let mut url = Url::parse(raw).map_err(|error| Error::InvalidConfiguration {
        message: format!("invalid {repository} repository URL {raw:?}: {error}"),
    })?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(Error::InvalidConfiguration {
            message: format!("{repository} repository URL must be an absolute HTTP(S) URL"),
        });
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::InvalidConfiguration {
            message: format!(
                "{repository} repository URL cannot contain credentials, a query, or a fragment"
            ),
        });
    }

    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url)
}

fn parse_credential_scope(raw: &str) -> Result<Url> {
    parse_base_url("credential scope", raw)
}

fn jsr_package_segments(package: &str) -> Result<(&str, &str)> {
    let Some((scope, name)) = package.split_once('/') else {
        return Err(Error::Resolution {
            package: package.to_owned(),
            message: "JSR package must be a scoped package such as @std/fs".to_owned(),
        });
    };
    if !scope.starts_with('@') || scope.len() == 1 || name.is_empty() || name.contains('/') {
        return Err(Error::Resolution {
            package: package.to_owned(),
            message: "JSR package must be a scoped package such as @std/fs".to_owned(),
        });
    }
    Ok((scope, name))
}

fn append_path_segments<'a>(
    base: &Url,
    segments: impl IntoIterator<Item = &'a str>,
) -> Result<Url> {
    let mut url = base.clone();
    let mut path = url
        .path_segments_mut()
        .map_err(|_| Error::InvalidConfiguration {
            message: format!("repository URL cannot accept path segments: {base}"),
        })?;
    path.pop_if_empty();
    for segment in segments {
        if segment.is_empty() {
            return Err(Error::Resolution {
                package: "artifact".to_owned(),
                message: "repository path contains an empty package or version segment".to_owned(),
            });
        }
        path.push(segment);
    }
    drop(path);
    Ok(url)
}

#[cfg(test)]
mod tests;
