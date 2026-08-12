use super::*;

#[test]
fn enforces_the_configured_pypi_artifact_base_for_metadata_urls() {
    let temporary = tempfile::tempdir().unwrap();
    let repositories = ArtifactRepositories::default()
        .with_pypi_artifact_base_url("https://artifacts.example.test/packages/")
        .unwrap();
    let fetcher = SourceFetcher::new(
        temporary.path().join("cache"),
        FetchPolicy {
            repositories,
            ..FetchPolicy::default()
        },
        EngineLimits::default(),
    )
    .unwrap();
    let dependency = dependency("*");

    assert!(
        fetcher
            .require_pypi_artifact_url(
                &dependency,
                Url::parse("https://artifacts.example.test/packages/example.tar.gz").unwrap(),
            )
            .is_ok()
    );
    for outside in [
        "https://artifacts.example.test/other/example.tar.gz",
        "https://artifacts.example.test/packages-evil/example.tar.gz",
        "https://other.example.test/packages/example.tar.gz",
        "http://artifacts.example.test/packages/example.tar.gz",
    ] {
        let error = fetcher
            .require_pypi_artifact_url(&dependency, Url::parse(outside).unwrap())
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("outside the configured artifact base")
        );
    }
}
