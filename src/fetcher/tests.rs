use super::{ArtifactRepositories, FetchPolicy, SourceFetcher, host_is_allowed};
use crate::{
    error::Error,
    model::{Dependency, Ecosystem, EngineLimits},
};

fn fetcher() -> (tempfile::TempDir, SourceFetcher) {
    let temporary = tempfile::tempdir().unwrap();
    let fetcher = SourceFetcher::new(
        temporary.path().join("cache"),
        FetchPolicy::default(),
        EngineLimits::default(),
    )
    .unwrap();
    (temporary, fetcher)
}

#[test]
fn rejects_http_configured_for_each_repository_by_default() {
    let repositories = [
        ArtifactRepositories::default()
            .with_npm_metadata_base_url("http://localhost:4873/npm")
            .unwrap(),
        ArtifactRepositories::default()
            .with_pypi_metadata_base_url("http://localhost:8080/pypi")
            .unwrap(),
        ArtifactRepositories::default()
            .with_jsr_metadata_base_url("http://localhost:8081/jsr")
            .unwrap(),
    ];

    for repositories in repositories {
        let temporary = tempfile::tempdir().unwrap();
        let error = SourceFetcher::new(
            temporary.path().join("cache"),
            FetchPolicy {
                repositories,
                ..FetchPolicy::default()
            },
            EngineLimits::default(),
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("uses insecure HTTP"));
    }
}

#[test]
fn permits_https_configured_repositories() {
    let temporary = tempfile::tempdir().unwrap();
    let repositories = ArtifactRepositories::new(
        "https://npm.example.test/registry",
        "https://pypi.example.test/simple",
        "https://jsr.example.test/registry",
    )
    .unwrap();
    assert!(
        SourceFetcher::new(
            temporary.path().join("cache"),
            FetchPolicy {
                repositories,
                ..FetchPolicy::default()
            },
            EngineLimits::default(),
        )
        .is_ok()
    );
}

#[test]
fn insecure_http_opt_in_is_limited_to_loopback_repositories() {
    let loopback = ArtifactRepositories::new(
        "http://localhost:4873/npm",
        "http://127.0.0.1:8080/pypi",
        "http://[::1]:8081/jsr",
    )
    .unwrap();
    let temporary = tempfile::tempdir().unwrap();
    assert!(
        SourceFetcher::new(
            temporary.path().join("loopback-cache"),
            FetchPolicy {
                repositories: loopback,
                allow_insecure_http: true,
                ..FetchPolicy::default()
            },
            EngineLimits::default(),
        )
        .is_ok()
    );

    let remote = ArtifactRepositories::default()
        .with_npm_metadata_base_url("http://packages.example.test/npm")
        .unwrap();
    let error = SourceFetcher::new(
        temporary.path().join("remote-cache"),
        FetchPolicy {
            repositories: remote,
            allow_insecure_http: true,
            ..FetchPolicy::default()
        },
        EngineLimits::default(),
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("non-loopback"));
}

#[test]
fn all_hosts_glob_allows_any_host() {
    assert!(host_is_allowed("example.com", &["*".to_owned()]));
    assert!(host_is_allowed("sub.example.com", &["*".to_owned()]));
}

#[test]
fn host_patterns_retain_existing_semantics() {
    assert!(host_is_allowed(
        "api.example.com",
        &["api.example.com".to_owned()]
    ));
    assert!(host_is_allowed(
        "api.example.com",
        &["*.example.com".to_owned()]
    ));
    assert!(!host_is_allowed(
        "example.com",
        &["*.example.com".to_owned()]
    ));
    assert!(!host_is_allowed(
        "notexample.com",
        &["*.example.com".to_owned()]
    ));
}

#[test]
fn host_patterns_are_case_insensitive() {
    assert!(host_is_allowed(
        "api.example.com",
        &["API.Example.COM".to_owned()]
    ));
    assert!(host_is_allowed(
        "Api.Example.Com",
        &["*.EXAMPLE.com".to_owned()]
    ));
    assert!(!host_is_allowed(
        "example.com",
        &["*.EXAMPLE.COM".to_owned()]
    ));
}

#[test]
fn remote_versions_are_bounded_by_the_package_limit() {
    let temporary = tempfile::tempdir().unwrap();
    let limits = EngineLimits {
        max_packages: 2,
        ..EngineLimits::default()
    };
    let fetcher = SourceFetcher::new(
        temporary.path().join("cache"),
        FetchPolicy::default(),
        limits,
    )
    .unwrap();

    fetcher.enforce_remote_version_limit(2).unwrap();
    let error = fetcher.enforce_remote_version_limit(3).unwrap_err();

    assert_eq!(error.code(), "limit_exceeded");
    assert!(error.to_string().contains("remote version roots"));
    assert!(error.to_string().contains("limit: 2"));
}

#[tokio::test]
async fn remote_version_count_must_provide_a_baseline() {
    let (_temporary, fetcher) = fetcher();

    for count in [0, 1] {
        let dependency = Dependency::declared(Ecosystem::Npm, "example", "npm:example");
        let error = fetcher
            .resolve_remote_versions(dependency, count)
            .await
            .unwrap_err();

        assert!(matches!(error, Error::InvalidConfiguration { .. }));
        assert!(error.to_string().contains("at least 2"));
    }
}

#[tokio::test]
async fn github_archive_acquisition_uses_the_canonical_validated_url() {
    let (_temporary, fetcher) = fetcher();
    let revision = "0123456789012345678901234567890123456789";
    let mut dependency = Dependency::declared(
        Ecosystem::Npm,
        "owner/repository",
        format!("owner/repository@{revision}"),
    );
    dependency.resolved_version = Some(revision.to_owned());
    dependency.source_url = Some(format!(
        "https://CODELOAD.GITHUB.COM:443/owner/repository/tar.gz/{revision}"
    ));

    assert_eq!(
        fetcher.artifact_url(&dependency).await.unwrap().as_str(),
        format!("https://codeload.github.com/owner/repository/tar.gz/{revision}")
    );
}

#[tokio::test]
async fn pinned_github_dependencies_have_no_registry_version_history() {
    let (_temporary, fetcher) = fetcher();
    let revision = "0123456789012345678901234567890123456789";
    let mut dependency = Dependency::declared(
        Ecosystem::Npm,
        "owner/repository",
        format!("owner/repository@{revision}"),
    );
    dependency.resolved_version = Some(revision.to_owned());
    dependency.source_url = Some(format!(
        "https://codeload.github.com/owner/repository/tar.gz/{revision}"
    ));

    let error = fetcher
        .resolve_remote_versions(dependency, 2)
        .await
        .unwrap_err();

    assert!(matches!(error, Error::InvalidConfiguration { .. }));
    assert!(error.to_string().contains("no registry version history"));
}
