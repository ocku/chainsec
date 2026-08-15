use super::{ScopedCredential, authorization_for};
use url::Url;

#[test]
fn credentials_are_scoped_by_https_host_port_and_route() {
    let credential = ScopedCredential::bearer(
        Url::parse("https://artifacts.example:8443/artifactory/api/npm/private/").unwrap(),
        "secret",
    )
    .unwrap();

    let authorization_for_url = |url: &str| {
        authorization_for(std::slice::from_ref(&credential), &Url::parse(url).unwrap())
            .unwrap()
            .is_some()
    };

    assert!(authorization_for_url(
        "https://artifacts.example:8443/artifactory/api/npm/private/package"
    ));

    for url in [
        // A different scheme must never receive a credential, even if all other
        // URL components are identical.
        "http://artifacts.example:8443/artifactory/api/npm/private/package",
        "https://other.example:8443/artifactory/api/npm/private/package",
        "https://artifacts.example:443/artifactory/api/npm/private/package",
        "https://artifacts.example:8443/artifactory/api/npm/public/package",
        "https://artifacts.example:8443/artifactory/api/npm/private-sibling/package",
    ] {
        assert!(!authorization_for_url(url), "credential leaked to {url}");
    }
}

#[test]
fn credentials_reject_ambiguous_escaped_paths() {
    let credential = ScopedCredential::bearer(
        Url::parse("https://packages.example/private/").unwrap(),
        "secret",
    )
    .unwrap();

    for path in [
        "/private/%2e%2e/public/collect",
        "/private/%2E%2E/public/collect",
        "/private/%2fpublic/collect",
        "/private/%5Cpublic/collect",
        "/private/%252e%252e/public/collect",
        "/private/%252fpublic/collect",
        "/private/%255cpublic/collect",
    ] {
        let url = Url::parse(&format!("https://packages.example{path}")).unwrap();
        assert!(
            authorization_for(std::slice::from_ref(&credential), &url)
                .unwrap()
                .is_none()
        );
    }
}
