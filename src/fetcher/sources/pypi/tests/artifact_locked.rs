use super::*;

#[test]
fn prefers_the_locked_artifact_digest() {
    let mut dependency = dependency("*");
    dependency.integrity =
        Some("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned());
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

#[test]
fn locked_python_artifact_must_match_a_non_yanked_digest() {
    let mut dependency = dependency("*");
    dependency.integrity =
        Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned());
    let metadata: PyPiMetadata = serde_json::from_str(
        r#"{
            "urls": [
                {"url": "https://example.test/yanked.tar.gz", "packagetype": "sdist", "yanked": true, "digests": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
                {"url": "https://example.test/other.tar.gz", "packagetype": "sdist", "digests": {"sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}
            ]
        }"#,
    )
    .unwrap();

    let error = select_locked_artifact(&dependency, &metadata).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("matching an authorized locked SHA-256 digest")
    );
}
