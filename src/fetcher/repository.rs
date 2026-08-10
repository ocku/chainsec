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

    pub(super) fn authorization_for(&self, url: &Url) -> Option<HeaderValue> {
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

fn parse_base_url(repository: &str, raw: &str) -> Result<Url> {
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
mod tests {
    use super::ArtifactRepositories;

    #[test]
    fn builds_repository_manager_metadata_urls_without_hard_coded_hosts() {
        let repositories = ArtifactRepositories::new(
            "https://artifacts.example/artifactory/api/npm/npm-remote",
            "https://artifacts.example/artifactory/api/pypi/pypi-remote/pypi",
            "https://artifacts.example/artifactory/jsr/jsr-remote",
        )
        .unwrap();

        assert_eq!(
            repositories
                .npm_metadata_url("@scope/package")
                .unwrap()
                .as_str(),
            "https://artifacts.example/artifactory/api/npm/npm-remote/@scope%2Fpackage"
        );
        assert_eq!(
            repositories
                .pypi_release_url("Example_Package", Some("1.2.3"))
                .unwrap()
                .as_str(),
            "https://artifacts.example/artifactory/api/pypi/pypi-remote/pypi/Example_Package/1.2.3/json"
        );
        assert_eq!(
            repositories.pypi_artifact_base_url().as_str(),
            "https://artifacts.example/artifactory/api/pypi/pypi-remote/pypi/"
        );
        assert_eq!(
            repositories
                .jsr_package_metadata_url("@scope/package")
                .unwrap()
                .as_str(),
            "https://artifacts.example/artifactory/jsr/jsr-remote/@scope/package/meta.json"
        );
        assert_eq!(
            repositories
                .jsr_version_metadata_url("@scope/package", "1.2.3")
                .unwrap()
                .as_str(),
            "https://artifacts.example/artifactory/jsr/jsr-remote/@scope/package/1.2.3_meta.json"
        );
    }

    #[test]
    fn builds_public_jsr_metadata_urls_with_scope_and_package_segments() {
        let repositories = ArtifactRepositories::default();

        assert_eq!(
            repositories
                .jsr_package_metadata_url("@std/fs")
                .unwrap()
                .as_str(),
            "https://jsr.io/@std/fs/meta.json"
        );
        assert_eq!(
            repositories
                .jsr_version_metadata_url("@std/fs", "1.0.0")
                .unwrap()
                .as_str(),
            "https://jsr.io/@std/fs/1.0.0_meta.json"
        );
    }

    #[test]
    fn applies_explicit_bearer_tokens_only_within_their_scope() {
        let repositories = ArtifactRepositories::default()
            .with_bearer_token("https://packages.example/private/", "secret")
            .unwrap();

        assert!(
            repositories
                .authorization_for(
                    &url::Url::parse("https://packages.example/private/package").unwrap()
                )
                .is_some()
        );
        assert!(
            repositories
                .authorization_for(
                    &url::Url::parse("https://packages.example/public/package").unwrap()
                )
                .is_none()
        );
    }
}
