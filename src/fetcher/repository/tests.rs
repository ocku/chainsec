use super::ArtifactRepositories;
use url::Url;

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
fn preserves_distinct_pypi_metadata_and_artifact_bases() {
    let repositories = ArtifactRepositories::default()
        .with_pypi_metadata_base_url("https://metadata.example/pypi")
        .unwrap()
        .with_pypi_artifact_base_url("https://artifacts.example/packages")
        .unwrap();

    assert_eq!(
        repositories
            .pypi_release_url("example", Some("1.0.0"))
            .unwrap()
            .as_str(),
        "https://metadata.example/pypi/example/1.0.0/json"
    );
    assert_eq!(
        repositories.pypi_artifact_base_url().as_str(),
        "https://artifacts.example/packages/"
    );
}

#[test]
fn uses_the_public_pypi_metadata_and_artifact_hosts_by_default() {
    let repositories = ArtifactRepositories::default();
    let urls = repositories.urls();

    assert_eq!(urls[1].host_str(), Some("pypi.org"));
    assert_eq!(urls[2].host_str(), Some("files.pythonhosted.org"));
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
fn permits_only_unambiguous_pypi_artifact_descendants() {
    let repositories = ArtifactRepositories::default()
        .with_pypi_artifact_base_url("https://artifacts.example/packages")
        .unwrap();

    for candidate in [
        "https://artifacts.example/packages",
        "https://artifacts.example/packages/",
        "https://artifacts.example/packages/example/example.whl",
    ] {
        assert!(
            repositories.pypi_artifact_url_is_permitted(&Url::parse(candidate).unwrap()),
            "expected {candidate} to be permitted"
        );
    }

    for candidate in [
        "https://artifacts.example/packages-sibling/example.whl",
        "https://artifacts.example/packages/%2e%2e/public/example.whl",
        "https://artifacts.example/packages/%2E%2E/public/example.whl",
        "https://artifacts.example/packages/%2fpublic/example.whl",
        "https://artifacts.example/packages/%2Fpublic/example.whl",
        "https://artifacts.example/packages/%5cpublic/example.whl",
        "https://artifacts.example/packages/%5Cpublic/example.whl",
        "https://artifacts.example/packages/%252e%252e/public/example.whl",
        "https://artifacts.example/packages/%252fpublic/example.whl",
        "https://artifacts.example/packages/%255cpublic/example.whl",
    ] {
        assert!(
            !repositories.pypi_artifact_url_is_permitted(&Url::parse(candidate).unwrap()),
            "expected {candidate} to be rejected"
        );
    }
}

#[test]
fn rejects_ambiguous_escaped_repository_base_paths() {
    for path in ["%25", "%2e", "%2E", "%2f", "%2F", "%5c", "%5C"] {
        let base = format!("https://artifacts.example/packages/{path}/private");
        assert!(matches!(
            ArtifactRepositories::default().with_pypi_artifact_base_url(base),
            Err(crate::Error::InvalidConfiguration { .. })
        ));
    }
}

#[test]
fn pypi_artifact_permission_preserves_origin_and_effective_port_checks() {
    let repositories = ArtifactRepositories::default()
        .with_pypi_artifact_base_url("https://artifacts.example:443/packages/")
        .unwrap();

    assert!(repositories.pypi_artifact_url_is_permitted(
        &Url::parse("https://artifacts.example/packages/example.whl").unwrap()
    ));
    for candidate in [
        "http://artifacts.example/packages/example.whl",
        "https://other.example/packages/example.whl",
        "https://artifacts.example:444/packages/example.whl",
    ] {
        assert!(!repositories.pypi_artifact_url_is_permitted(&Url::parse(candidate).unwrap()));
    }
}

#[test]
fn rejects_insecure_or_malformed_bearer_token_scopes() {
    for scope in [
        "ftp://packages.example/private/",
        "https://packages.example/private/%252e%252e/public/",
        "https://user@packages.example/private/",
        "https://packages.example/private/?query=value",
        "https://packages.example/private/#fragment",
    ] {
        assert!(matches!(
            ArtifactRepositories::default().with_bearer_token(scope, "secret"),
            Err(crate::Error::InvalidConfiguration { .. })
        ));
    }
}

#[test]
fn accepts_http_repository_urls_until_a_fetch_policy_is_applied() {
    assert!(
        ArtifactRepositories::new(
            "http://localhost:4873/npm",
            "http://127.0.0.1:8080/pypi",
            "http://[::1]:8081/jsr",
        )
        .is_ok()
    );
}

#[test]
fn environment_bearer_tokens_are_resolved_only_for_matching_requests() {
    let variable = format!("CHAINSEC_TEST_MISSING_TOKEN_{}", std::process::id());
    let repositories = ArtifactRepositories::default()
        .with_bearer_token_environment("https://packages.example/private/", &variable)
        .unwrap();

    assert!(
        repositories
            .authorization_for(&url::Url::parse("https://packages.example/public/package").unwrap())
            .unwrap()
            .is_none()
    );
    assert!(
        repositories
            .authorization_for(
                &url::Url::parse("https://packages.example/private/package").unwrap()
            )
            .is_err()
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
            .unwrap()
            .is_some()
    );
    assert!(
        repositories
            .authorization_for(&url::Url::parse("https://packages.example/public/package").unwrap())
            .unwrap()
            .is_none()
    );
}
