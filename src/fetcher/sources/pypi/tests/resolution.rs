use super::*;

#[test]
fn resolves_latest_matching_source_distribution() {
    let mut dependency = dependency("example>=1.0,<2.0");
    let metadata: PyPiMetadata = serde_json::from_str(
        r#"{
            "releases": {
                "1.0.0": [{"url": "https://example.test/example-1.0.0.tar.gz", "packagetype": "sdist", "digests": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}],
                "1.5.0": [{"url": "https://example.test/example-1.5.0.tar.gz", "packagetype": "sdist", "digests": {"sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}],
                "2.0.0": [{"url": "https://example.test/example-2.0.0.tar.gz", "packagetype": "sdist", "digests": {"sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}]
            }
        }"#,
    )
    .unwrap();

    resolve_python_release(&mut dependency, &metadata).unwrap();

    assert_eq!(dependency.resolved_version.as_deref(), Some("1.5.0"));
    assert_eq!(
        dependency.source_url.as_deref(),
        Some("https://example.test/example-1.5.0.tar.gz")
    );
    assert_eq!(
        dependency.integrity.as_deref(),
        Some("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    );
}

#[test]
fn unlocked_python_resolution_prefers_final_releases_by_default() {
    let mut dependency = dependency("example>=1.0");
    let metadata: PyPiMetadata = serde_json::from_str(
        r#"{
            "releases": {
                "1.0": [{"url": "https://example.test/example-1.0.tar.gz", "packagetype": "sdist", "digests": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}],
                "2.0rc1": [{"url": "https://example.test/example-2.0rc1.tar.gz", "packagetype": "sdist", "digests": {"sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}]
            }
        }"#,
    )
    .unwrap();

    resolve_python_release(&mut dependency, &metadata).unwrap();

    assert_eq!(dependency.resolved_version.as_deref(), Some("1.0"));
}

#[test]
fn unlocked_python_resolution_uses_prereleases_when_only_prereleases_match() {
    let mut dependency = dependency("example>=2.0");
    let metadata: PyPiMetadata = serde_json::from_str(
        r#"{
            "releases": {
                "1.9": [{"url": "https://example.test/example-1.9.tar.gz", "packagetype": "sdist", "digests": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}],
                "2.1a1": [{"url": "https://example.test/example-2.1a1.tar.gz", "packagetype": "sdist", "digests": {"sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}],
                "2.1rc1": [{"url": "https://example.test/example-2.1rc1.tar.gz", "packagetype": "sdist", "digests": {"sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}]
            }
        }"#,
    )
    .unwrap();

    resolve_python_release(&mut dependency, &metadata).unwrap();

    assert_eq!(dependency.resolved_version.as_deref(), Some("2.1rc1"));
}

#[test]
fn unlocked_python_resolution_honors_explicit_prerelease_opt_in() {
    let mut dependency = dependency("example>=1.0rc1");
    let metadata: PyPiMetadata = serde_json::from_str(
        r#"{
            "releases": {
                "1.0rc1": [{"url": "https://example.test/example-1.0rc1.tar.gz", "packagetype": "sdist", "digests": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}],
                "1.0": [{"url": "https://example.test/example-1.0.tar.gz", "packagetype": "sdist", "digests": {"sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}],
                "2.0rc1": [{"url": "https://example.test/example-2.0rc1.tar.gz", "packagetype": "sdist", "digests": {"sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}]
            }
        }"#,
    )
    .unwrap();

    resolve_python_release(&mut dependency, &metadata).unwrap();

    assert_eq!(dependency.resolved_version.as_deref(), Some("2.0rc1"));
}

#[test]
fn retains_requires_python_without_assuming_a_target_interpreter() {
    let mut dependency = dependency("example==1.0");
    let metadata: PyPiMetadata = serde_json::from_str(
        r#"{
            "releases": {
                "1.0": [{
                    "url": "https://example.test/example-1.0.tar.gz",
                    "packagetype": "sdist",
                    "requires_python": ">=99",
                    "digests": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
                }]
            }
        }"#,
    )
    .unwrap();
    let artifact = &metadata.releases.as_ref().unwrap()["1.0"][0];

    assert_eq!(artifact.requires_python(), Some(">=99"));
    resolve_python_release(&mut dependency, &metadata).unwrap();
    assert_eq!(dependency.resolved_version.as_deref(), Some("1.0"));
}

#[test]
fn unlocked_python_resolution_rejects_wheel_only_releases() {
    let mut dependency = dependency("example==1.0");
    let metadata: PyPiMetadata = serde_json::from_str(
        r#"{
            "releases": {
                "1.0": [
                    {"url": "https://example.test/example-1.0-py3-none-any.whl", "packagetype": "bdist_wheel", "digests": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
                    {"url": "https://example.test/example-1.0-cp313-linux_x86_64.whl", "packagetype": "bdist_wheel", "digests": {"sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}
                ]
            }
        }"#,
    )
    .unwrap();

    let error = resolve_python_release(&mut dependency, &metadata).unwrap_err();

    assert!(error.to_string().contains("source distribution"));
    assert!(dependency.resolved_version.is_none());
    assert!(dependency.source_url.is_none());
    assert!(dependency.integrity.is_none());
}
