use std::collections::BTreeMap;

use serde::Deserialize;

use crate::{error::Result, model::Dependency};

use super::resolution_error;

#[derive(Debug, Deserialize)]
pub(super) struct PyPiMetadata {
    #[serde(default)]
    pub(super) releases: Option<BTreeMap<String, Vec<PyPiArtifact>>>,
    #[serde(default)]
    pub(super) urls: Option<Vec<PyPiArtifact>>,
}

#[derive(Debug, Deserialize)]
pub(super) struct PyPiArtifact {
    pub(super) url: Option<String>,
    #[serde(default)]
    digests: Option<PyPiDigests>,
    #[serde(default)]
    yanked: bool,
    packagetype: Option<String>,
    // Retain this metadata for callers that gain a target interpreter context. Chainsec does not
    // currently model one, so using it to reject artifacts would imply installer equivalence that
    // the resolver cannot provide.
    #[serde(default)]
    requires_python: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PyPiDigests {
    sha256: Option<String>,
}

impl PyPiArtifact {
    pub(super) fn sha256(&self) -> Option<&str> {
        self.digests.as_ref()?.sha256.as_deref()
    }

    fn is_source_distribution(&self) -> bool {
        self.packagetype.as_deref() == Some("sdist")
    }

    pub(super) fn requires_python(&self) -> Option<&str> {
        self.requires_python.as_deref()
    }

    fn is_usable(&self) -> bool {
        // `requires_python` remains advisory until resolution has an explicit target interpreter.
        let _ = self.requires_python();
        !self.yanked && self.url.is_some() && self.sha256().is_some_and(is_sha256_digest)
    }
}

pub(super) fn python_releases<'a>(
    dependency: &Dependency,
    metadata: &'a PyPiMetadata,
) -> Result<&'a BTreeMap<String, Vec<PyPiArtifact>>> {
    metadata
        .releases
        .as_ref()
        .ok_or_else(|| resolution_error(dependency, "PyPI response has no releases"))
}

pub(super) fn pin_python_release(
    dependency: &mut Dependency,
    version: &str,
    artifact: &PyPiArtifact,
) {
    dependency.resolved_version = Some(version.to_owned());
    dependency.source_url = artifact.url.clone();
    dependency.integrity = artifact.sha256().map(|digest| format!("sha256:{digest}"));
}

pub(super) fn select_locked_artifact<'a>(
    dependency: &Dependency,
    metadata: &'a PyPiMetadata,
) -> Result<&'a PyPiArtifact> {
    let artifacts = metadata
        .urls
        .as_deref()
        .ok_or_else(|| resolution_error(dependency, "PyPI response has no artifacts"))?;
    let expected_digests = dependency
        .integrity
        .as_deref()
        .into_iter()
        .flat_map(str::split_whitespace)
        .filter_map(|value| value.strip_prefix("sha256:"))
        .collect::<Vec<_>>();

    if !expected_digests.is_empty() {
        return artifacts
            .iter()
            .find(|artifact| {
                artifact.is_usable()
                    && artifact
                        .sha256()
                        .is_some_and(|digest| expected_digests.contains(&digest))
            })
            .ok_or_else(|| {
                resolution_error(
                    dependency,
                    "PyPI response has no non-yanked artifact matching an authorized locked SHA-256 digest",
                )
            });
    }

    select_source_distribution(artifacts).ok_or_else(|| {
        resolution_error(
            dependency,
            "PyPI response has no non-yanked source distribution with SHA-256 integrity",
        )
    })
}

pub(super) fn select_source_distribution(artifacts: &[PyPiArtifact]) -> Option<&PyPiArtifact> {
    artifacts
        .iter()
        .find(|artifact| artifact.is_usable() && artifact.is_source_distribution())
}

fn is_sha256_digest(digest: &str) -> bool {
    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}
