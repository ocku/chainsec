use super::{Dependency, Ecosystem};

const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

fn dependency(url: &str) -> Dependency {
    let mut dependency = Dependency::declared(Ecosystem::Npm, "example", "example");
    dependency.resolved_version = Some(REVISION.to_owned());
    dependency.source_url = Some(url.to_owned());
    dependency
}

#[test]
fn classifies_npm_local_schemes_as_local() {
    for requirement in [
        "file:../package",
        "link:../package",
        "portal:../package",
        "workspace:*",
    ] {
        let dependency = Dependency::declared(Ecosystem::Npm, "example", requirement);
        assert!(dependency.is_local(), "accepted as remote: {requirement}");
    }

    let dependency = Dependency::declared(Ecosystem::Npm, "example", "^1.0.0");
    assert!(!dependency.is_local());
}

#[test]
fn accepts_canonical_github_commit_archive() {
    let dependency = dependency(&format!(
        "https://codeload.github.com/owner/repository/tar.gz/{REVISION}"
    ));

    assert!(dependency.is_pinned_github());
    assert!(dependency.is_resolved());
    assert_eq!(
        dependency.github_archive_url().unwrap().as_str(),
        format!("https://codeload.github.com/owner/repository/tar.gz/{REVISION}")
    );
}

#[test]
fn rejects_noncanonical_github_archive_urls() {
    let cases = [
        format!("https://codeload.github.com.attacker.example/owner/repository/tar.gz/{REVISION}"),
        format!("https://codeload.github.com@attacker.example/owner/repository/tar.gz/{REVISION}"),
        format!("http://codeload.github.com/owner/repository/tar.gz/{REVISION}"),
        format!("https://codeload.github.com:444/owner/repository/tar.gz/{REVISION}"),
        format!("https://user@codeload.github.com/owner/repository/tar.gz/{REVISION}"),
        format!("https://codeload.github.com/owner/repository/tar.gz/{REVISION}?download=1"),
        format!("https://codeload.github.com/owner/repository/tar.gz/{REVISION}#archive"),
        format!("https://codeload.github.com/owner/repository/zip/{REVISION}"),
        "https://codeload.github.com/owner/repository/tar.gz/short".to_owned(),
        format!("https://codeload.github.com/owner%2Frepository/tar.gz/{REVISION}"),
        format!("https://codeload.github.com/owner/repository/tar.gz/{REVISION}/extra"),
        "https://codeload.github.com/owner/repository/tar.gz/ffffffffffffffffffffffffffffffffffffffff"
            .to_owned(),
    ];

    for url in cases {
        let dependency = dependency(&url);
        assert!(!dependency.is_pinned_github(), "accepted {url}");
        assert!(!dependency.is_resolved(), "resolved {url}");
    }
}
