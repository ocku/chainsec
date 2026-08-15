use super::*;

#[test]
fn permits_the_configured_pypi_artifact_base_or_an_explicitly_allowed_host() {
    let temporary = tempfile::tempdir().unwrap();
    let repositories = ArtifactRepositories::default()
        .with_pypi_artifact_base_url("https://artifacts.example.test/packages/")
        .unwrap();
    let fetcher = SourceFetcher::new(
        temporary.path().join("cache"),
        FetchPolicy {
            allowed_hosts: vec!["cdn.example.test".to_owned()],
            repositories,
            ..FetchPolicy::default()
        },
        EngineLimits::default(),
    )
    .unwrap();
    let dependency = dependency("*");

    for permitted in [
        "https://artifacts.example.test/packages/example.tar.gz",
        "https://cdn.example.test/releases/example.tar.gz",
    ] {
        assert!(
            fetcher
                .require_pypi_artifact_url(&dependency, Url::parse(permitted).unwrap())
                .is_ok(),
            "expected {permitted} to be permitted"
        );
    }
}

#[test]
fn allowed_external_pypi_artifacts_do_not_inherit_repository_credentials() {
    let temporary = tempfile::tempdir().unwrap();
    let repositories = ArtifactRepositories::default()
        .with_npm_metadata_base_url("https://cdn.example.test/releases/")
        .unwrap()
        .with_pypi_artifact_base_url("https://artifacts.example.test/packages/")
        .unwrap()
        .with_bearer_token("https://cdn.example.test/releases/", "secret")
        .unwrap();
    let fetcher = SourceFetcher::new(
        temporary.path().join("cache"),
        FetchPolicy {
            allowed_hosts: vec!["cdn.example.test".to_owned()],
            repositories,
            ..FetchPolicy::default()
        },
        EngineLimits::default(),
    )
    .unwrap();
    let dependency = dependency("*");
    let url = Url::parse("https://cdn.example.test/releases/example.tar.gz").unwrap();

    assert!(
        fetcher
            .policy
            .repositories
            .authorization_for(&url)
            .unwrap()
            .is_some()
    );
    assert!(
        fetcher
            .require_pypi_artifact_url(&dependency, url.clone())
            .is_ok()
    );
    let repository_request = fetcher.effective_artifact_repository_request(&dependency, &url, true);
    assert!(!repository_request);
    assert!(
        fetcher
            .request_provenance(&url, repository_request)
            .repository_base
            .is_none()
    );
}

#[test]
fn applies_normal_url_policy_outside_the_configured_pypi_artifact_base() {
    let temporary = tempfile::tempdir().unwrap();
    let repositories = ArtifactRepositories::default()
        .with_pypi_artifact_base_url("https://artifacts.example.test/packages/")
        .unwrap();
    let fetcher = SourceFetcher::new(
        temporary.path().join("cache"),
        FetchPolicy {
            allowed_hosts: vec!["cdn.example.test".to_owned()],
            repositories,
            ..FetchPolicy::default()
        },
        EngineLimits::default(),
    )
    .unwrap();
    let dependency = dependency("*");

    for (url, expected) in [
        (
            "https://untrusted-cdn.example.test/example.tar.gz",
            "not in the allowlist",
        ),
        ("http://cdn.example.test/example.tar.gz", "insecure URL"),
        (
            "https://token@cdn.example.test/example.tar.gz",
            "URL credentials are forbidden",
        ),
    ] {
        let error = fetcher
            .require_pypi_artifact_url(&dependency, Url::parse(url).unwrap())
            .unwrap_err();
        assert!(
            error.to_string().contains(expected),
            "expected {url} to be rejected with {expected:?}, got {error}"
        );
    }
}
