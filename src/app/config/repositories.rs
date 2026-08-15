use chainsec::ArtifactRepositories;
use serde::Deserialize;
use url::Url;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::app) struct ArtifactoriesConfig {
    npm: Option<ArtifactoryConfig>,
    pypi: Option<PyPiArtifactoryConfig>,
    jsr: Option<ArtifactoryConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactoryConfig {
    metadata_base_url: String,
    credential: Option<CredentialConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PyPiArtifactoryConfig {
    metadata_base_url: String,
    artifact_base_url: Option<String>,
    credential: Option<CredentialConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialConfig {
    scope: String,
    bearer_token_env: String,
}

impl CredentialConfig {
    fn apply_to(
        self,
        repositories: ArtifactRepositories,
    ) -> chainsec::Result<ArtifactRepositories> {
        repositories.with_bearer_token_environment(self.scope, self.bearer_token_env)
    }
}

impl ArtifactoriesConfig {
    pub(super) fn overlay(self, overriding: Self) -> Self {
        Self {
            npm: overriding.npm.or(self.npm),
            pypi: overriding.pypi.or(self.pypi),
            jsr: overriding.jsr.or(self.jsr),
        }
    }

    pub(super) fn apply_to(
        self,
        repositories: ArtifactRepositories,
    ) -> chainsec::Result<(ArtifactRepositories, Vec<String>)> {
        let (repositories, npm_host) =
            apply_artifactory(repositories, self.npm, |repositories, url| {
                repositories.with_npm_metadata_base_url(url)
            })?;
        let (repositories, pypi_hosts) = apply_pypi_artifactory(repositories, self.pypi)?;
        let (repositories, jsr_host) =
            apply_artifactory(repositories, self.jsr, |repositories, url| {
                repositories.with_jsr_metadata_base_url(url)
            })?;
        Ok((
            repositories,
            [npm_host, jsr_host]
                .into_iter()
                .flatten()
                .chain(pypi_hosts)
                .collect(),
        ))
    }
}

fn apply_pypi_artifactory(
    repositories: ArtifactRepositories,
    artifactory: Option<PyPiArtifactoryConfig>,
) -> chainsec::Result<(ArtifactRepositories, Vec<String>)> {
    let Some(artifactory) = artifactory else {
        return Ok((repositories, Vec::new()));
    };

    let metadata_base_url = artifactory.metadata_base_url;
    // Apply the override after metadata regardless of TOML field order; otherwise
    // the metadata setter intentionally restores its artifact-base default.
    let mut repositories = repositories.with_pypi_metadata_base_url(&metadata_base_url)?;
    let mut hosts = vec![repository_host(&metadata_base_url, "PyPI metadata")];
    if let Some(artifact_base_url) = artifactory.artifact_base_url {
        repositories = repositories.with_pypi_artifact_base_url(&artifact_base_url)?;
        let artifact_host = repository_host(&artifact_base_url, "PyPI artifact");
        if !hosts.contains(&artifact_host) {
            hosts.push(artifact_host);
        }
    }
    let repositories = match artifactory.credential {
        Some(credential) => credential.apply_to(repositories)?,
        None => repositories,
    };
    Ok((repositories, hosts))
}

fn repository_host(url: &str, repository: &str) -> String {
    let url = Url::parse(url).unwrap_or_else(|_| panic!("validated {repository} URL"));
    url.host_str()
        .unwrap_or_else(|| panic!("validated {repository} URL has a host"))
        .to_owned()
}

fn apply_artifactory(
    repositories: ArtifactRepositories,
    artifactory: Option<ArtifactoryConfig>,
    set_metadata_url: impl FnOnce(
        ArtifactRepositories,
        String,
    ) -> chainsec::Result<ArtifactRepositories>,
) -> chainsec::Result<(ArtifactRepositories, Option<String>)> {
    let Some(artifactory) = artifactory else {
        return Ok((repositories, None));
    };

    let metadata_base_url = artifactory.metadata_base_url;
    let repositories = set_metadata_url(repositories, metadata_base_url.clone())?;
    let host = repository_host(&metadata_base_url, "Artifactory metadata");
    let repositories = match artifactory.credential {
        Some(credential) => credential.apply_to(repositories)?,
        None => repositories,
    };
    Ok((repositories, Some(host)))
}
