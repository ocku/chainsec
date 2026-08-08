use std::{collections::BTreeMap, path::Path, str::FromStr};

use pep440_rs::{Version, VersionSpecifiers};
use serde::Deserialize;
use url::Url;

use crate::{
    error::{Error, Result},
    model::{Dependency, FetchMetadata},
};

use crate::fetcher::SourceFetcher;

#[derive(Debug, Deserialize)]
struct PyPiMetadata {
    #[serde(default)]
    releases: Option<BTreeMap<String, Vec<PyPiArtifact>>>,
    #[serde(default)]
    urls: Option<Vec<PyPiArtifact>>,
}

#[derive(Debug, Deserialize)]
struct PyPiArtifact {
    url: Option<String>,
    #[serde(default)]
    digests: Option<PyPiDigests>,
    #[serde(default)]
    yanked: bool,
    packagetype: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PyPiDigests {
    sha256: Option<String>,
}

impl PyPiArtifact {
    fn sha256(&self) -> Option<&str> {
        self.digests.as_ref()?.sha256.as_deref()
    }

    fn is_source_distribution(&self) -> bool {
        self.packagetype.as_deref() == Some("sdist")
    }

    fn is_usable(&self) -> bool {
        !self.yanked && self.url.is_some() && self.sha256().is_some_and(is_sha256_digest)
    }
}

impl SourceFetcher {
    pub(in crate::fetcher) async fn fetch_python_package(
        &self,
        dependency: &Dependency,
        url: &Url,
        temporary: &Path,
    ) -> Result<FetchMetadata> {
        self.fetch_standalone_archive(dependency, url, temporary)
            .await
    }

    pub(in crate::fetcher) async fn resolve_unlocked_python(
        &self,
        dependency: &mut Dependency,
    ) -> Result<()> {
        let api = self
            .policy
            .repositories
            .pypi_release_url(&dependency.name, None)?;
        let metadata = self.pypi_metadata(dependency, &api).await?;
        resolve_python_release(dependency, &metadata)
    }

    pub(in crate::fetcher) async fn python_artifact_url(
        &self,
        dependency: &Dependency,
    ) -> Result<Url> {
        if let Some(source_url) = dependency.source_url.as_deref() {
            return parse_artifact_url(dependency, source_url);
        }

        let version = dependency
            .resolved_version
            .as_deref()
            .ok_or_else(|| resolution_error(dependency, "locked version is missing"))?;
        let api = self
            .policy
            .repositories
            .pypi_release_url(&dependency.name, Some(version))?;
        let metadata = self.pypi_metadata(dependency, &api).await?;
        let artifact = select_locked_artifact(dependency, &metadata)?;
        let url = artifact
            .url
            .as_deref()
            .ok_or_else(|| resolution_error(dependency, "artifact URL is missing"))?;
        parse_artifact_url(dependency, url)
    }

    async fn pypi_metadata(&self, dependency: &Dependency, api: &Url) -> Result<PyPiMetadata> {
        serde_json::from_slice(&self.download(api).await?).map_err(|error| Error::Resolution {
            package: dependency.id(),
            message: format!("invalid PyPI response: {error}"),
        })
    }
}

fn resolve_python_release(dependency: &mut Dependency, metadata: &PyPiMetadata) -> Result<()> {
    let specifier = python_specifier(dependency)?;
    let releases = metadata
        .releases
        .as_ref()
        .ok_or_else(|| resolution_error(dependency, "PyPI response has no releases"))?;
    let selected = releases
        .iter()
        .filter_map(|(raw_version, artifacts)| {
            let version = Version::from_str(raw_version).ok()?;
            specifier
                .as_ref()
                .is_none_or(|specifier| specifier.contains(&version))
                .then(|| {
                    select_resolvable_artifact(artifacts)
                        .map(|artifact| (version, raw_version, artifact))
                })
                .flatten()
        })
        .max_by(|(left, ..), (right, ..)| left.cmp(right))
        .ok_or_else(|| {
            resolution_error(
                dependency,
                format!(
                    "PyPI has no non-yanked artifact satisfying {}",
                    dependency.requirement
                ),
            )
        })?;

    let (_, version, artifact) = selected;
    dependency.resolved_version = Some(version.to_owned());
    dependency.source_url = artifact.url.clone();
    dependency.integrity = artifact.sha256().map(|digest| format!("sha256:{digest}"));
    Ok(())
}

fn select_locked_artifact<'a>(
    dependency: &Dependency,
    metadata: &'a PyPiMetadata,
) -> Result<&'a PyPiArtifact> {
    let artifacts = metadata
        .urls
        .as_deref()
        .ok_or_else(|| resolution_error(dependency, "PyPI response has no artifacts"))?;
    let expected_digest = dependency
        .integrity
        .as_deref()
        .and_then(|value| value.strip_prefix("sha256:"));

    artifacts
        .iter()
        .find(|artifact| expected_digest.is_some_and(|digest| artifact.sha256() == Some(digest)))
        .or_else(|| {
            artifacts
                .iter()
                .find(|artifact| artifact.is_source_distribution())
        })
        .or_else(|| artifacts.first())
        .ok_or_else(|| resolution_error(dependency, "PyPI response has no usable artifact"))
}

fn select_resolvable_artifact(artifacts: &[PyPiArtifact]) -> Option<&PyPiArtifact> {
    artifacts
        .iter()
        .filter(|artifact| artifact.is_usable())
        .find(|artifact| artifact.is_source_distribution())
        .or_else(|| artifacts.iter().find(|artifact| artifact.is_usable()))
}

fn parse_artifact_url(dependency: &Dependency, raw_url: &str) -> Result<Url> {
    Url::parse(raw_url).map_err(|error| resolution_error(dependency, error.to_string()))
}

fn python_specifier(dependency: &Dependency) -> Result<Option<VersionSpecifiers>> {
    let requirement = dependency
        .requirement
        .split(';')
        .next()
        .unwrap_or(&dependency.requirement)
        .trim();
    let mut raw = requirement
        .strip_prefix(&dependency.name)
        .unwrap_or(requirement)
        .trim();
    if raw.starts_with('[')
        && let Some(end) = raw.find(']')
    {
        raw = raw[end + 1..].trim();
    }
    if raw.is_empty() || raw == "*" {
        return Ok(None);
    }

    VersionSpecifiers::from_str(raw).map(Some).map_err(|error| {
        resolution_error(
            dependency,
            format!("unsupported Python version requirement {raw:?}: {error}"),
        )
    })
}

fn is_sha256_digest(digest: &str) -> bool {
    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn resolution_error(dependency: &Dependency, message: impl Into<String>) -> Error {
    Error::Resolution {
        package: dependency.id(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Ecosystem;

    fn dependency(requirement: &str) -> Dependency {
        Dependency::declared(Ecosystem::Python, "example", requirement)
    }

    #[test]
    fn resolves_latest_matching_source_distribution() {
        let mut dependency = dependency("example>=1.0,<2.0");
        let metadata: PyPiMetadata = serde_json::from_str(
            r#"{
                "releases": {
                    "1.0.0": [{"url": "https://example.test/example-1.0.0.tar.gz", "packagetype": "sdist", "digests": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}],
                    "1.5.0": [{"url": "https://example.test/example-1.5.0.tar.gz", "packagetype": "sdist", "digests": {"sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}],
                    "2.0.0": [{"url": "https://example.test/example-2.0.0.tar.gz", "packagetype": "sdist", "digests": {"sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}]
                }
            }"#,
        )
        .unwrap();

        resolve_python_release(&mut dependency, &metadata).unwrap();

        assert_eq!(dependency.resolved_version.as_deref(), Some("1.5.0"));
        assert_eq!(
            dependency.source_url.as_deref(),
            Some("https://example.test/example-1.5.0.tar.gz")
        );
        assert_eq!(
            dependency.integrity.as_deref(),
            Some("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );
    }

    #[test]
    fn prefers_the_locked_artifact_digest() {
        let mut dependency = dependency("*");
        dependency.integrity = Some(
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        );
        let metadata: PyPiMetadata = serde_json::from_str(
            r#"{
                "urls": [
                    {"url": "https://example.test/source.tar.gz", "packagetype": "sdist", "digests": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
                    {"url": "https://example.test/wheel.whl", "packagetype": "bdist_wheel", "digests": {"sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}
                ]
            }"#,
        )
        .unwrap();

        let artifact = select_locked_artifact(&dependency, &metadata).unwrap();

        assert_eq!(
            artifact.url.as_deref(),
            Some("https://example.test/wheel.whl")
        );
    }
}
