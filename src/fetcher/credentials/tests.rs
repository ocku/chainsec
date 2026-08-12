use super::{ScopedCredential, authorization_for};
use url::Url;

#[test]
fn credentials_are_scoped_by_host_and_path() {
    let credential = ScopedCredential::bearer(
        Url::parse("https://artifacts.example/artifactory/api/npm/private/").unwrap(),
        "secret",
    )
    .unwrap();
    assert!(
        authorization_for(
            std::slice::from_ref(&credential),
            &Url::parse("https://artifacts.example/artifactory/api/npm/private/package").unwrap()
        )
        .unwrap()
        .is_some()
    );
    assert!(
        authorization_for(
            std::slice::from_ref(&credential),
            &Url::parse("https://artifacts.example/artifactory/api/npm/public/package").unwrap()
        )
        .unwrap()
        .is_none()
    );
    assert!(
        authorization_for(
            std::slice::from_ref(&credential),
            &Url::parse("http://artifacts.example/artifactory/api/npm/private/package").unwrap()
        )
        .unwrap()
        .is_none()
    );
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
