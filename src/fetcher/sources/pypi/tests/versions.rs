use super::*;

#[test]
fn returns_selected_and_older_pullable_pypi_versions_in_pep440_order() {
    let metadata: PyPiMetadata = serde_json::from_str(
        r#"{
            "releases": {
                "10.0": [{"url": "https://example.test/10.tar.gz", "packagetype": "sdist", "digests": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}],
                "2.0": [{"url": "https://example.test/2.tar.gz", "packagetype": "sdist", "digests": {"sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}],
                "1.10": [{"url": "https://example.test/1.10.tar.gz", "packagetype": "sdist", "yanked": true, "digests": {"sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}],
                "1.9": [{"url": "https://example.test/1.9.tar.gz", "packagetype": "sdist", "digests": {"sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}}],
                "1.8": [{"url": "https://example.test/1.8.tar.gz", "packagetype": "sdist", "digests": {"sha256": "not-a-digest"}}],
                "1.7": [{"url": "https://example.test/1.7.whl", "packagetype": "bdist_wheel", "digests": {"sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}}]
            }
        }"#,
    )
    .unwrap();
    let mut selected = dependency("example==2.0");
    resolve_python_release(&mut selected, &metadata).unwrap();

    assert_eq!(
        test_fetcher(usize::MAX)
            .1
            .python_versions_at_or_below(selected.clone(), 1, &metadata)
            .unwrap()
            .len(),
        1
    );
    let error = test_fetcher(2)
        .1
        .python_versions_at_or_below(selected.clone(), 3, &metadata)
        .unwrap_err();
    assert_eq!(error.code(), "limit_exceeded");
    assert!(error.to_string().contains("remote version candidates"));

    let versions = test_fetcher(usize::MAX)
        .1
        .python_versions_at_or_below(selected, 3, &metadata)
        .unwrap();

    assert_eq!(
        versions
            .iter()
            .map(|dependency| dependency.resolved_version.as_deref().unwrap())
            .collect::<Vec<_>>(),
        ["2.0", "1.9"]
    );
    assert!(versions.iter().all(Dependency::is_resolved));
    assert!(
        versions
            .iter()
            .all(|dependency| dependency.source_url.is_some())
    );
}

#[test]
fn compares_exact_pullable_pypi_endpoints_in_to_from_order() {
    let metadata: PyPiMetadata = serde_json::from_str(
        r#"{
            "releases": {
                "1.0": [{"url": "https://example.test/1.tar.gz", "packagetype": "sdist", "digests": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}],
                "1.5": [{"url": "https://example.test/1.5.tar.gz", "packagetype": "sdist", "digests": {"sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}],
                "2.0": [{"url": "https://example.test/2.tar.gz", "packagetype": "sdist", "digests": {"sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}]
            }
        }"#,
    )
    .unwrap();

    let versions = python_compare_versions(&dependency("*"), "1.0", "2.0", &metadata).unwrap();

    assert_eq!(
        versions
            .iter()
            .map(|dependency| dependency.resolved_version.as_deref().unwrap())
            .collect::<Vec<_>>(),
        ["2.0", "1.0"]
    );
}

#[test]
fn ranges_include_endpoints_and_skip_unpullable_pypi_intermediates() {
    let metadata: PyPiMetadata = serde_json::from_str(
        r#"{
            "releases": {
                "0.9": [{"url": "https://example.test/0.9.tar.gz", "packagetype": "sdist", "digests": {"sha256": "0000000000000000000000000000000000000000000000000000000000000000"}}],
                "1.0": [{"url": "https://example.test/1.tar.gz", "packagetype": "sdist", "digests": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}],
                "1.4": [{"url": "https://example.test/1.4.tar.gz", "packagetype": "sdist", "yanked": true, "digests": {"sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}],
                "1.6": [{"url": "https://example.test/1.6.whl", "packagetype": "bdist_wheel", "digests": {"sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}],
                "2.0": [{"url": "https://example.test/2.tar.gz", "packagetype": "sdist", "digests": {"sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}}],
                "3.0": [{"url": "https://example.test/3.tar.gz", "packagetype": "sdist", "digests": {"sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}}]
            }
        }"#,
    )
    .unwrap();

    let error = test_fetcher(2)
        .1
        .python_range_versions(&dependency("*"), "1.0", "2.0", &metadata)
        .unwrap_err();
    assert_eq!(error.code(), "limit_exceeded");
    assert!(error.to_string().contains("remote version candidates"));

    let versions = test_fetcher(usize::MAX)
        .1
        .python_range_versions(&dependency("*"), "1.0", "2.0", &metadata)
        .unwrap();

    assert_eq!(
        versions
            .iter()
            .map(|dependency| dependency.resolved_version.as_deref().unwrap())
            .collect::<Vec<_>>(),
        ["2.0", "1.0"]
    );
}

#[test]
fn rejects_yanked_equal_and_reversed_pypi_endpoints() {
    let metadata: PyPiMetadata = serde_json::from_str(
        r#"{
            "releases": {
                "1.0": [{"url": "https://example.test/1.tar.gz", "packagetype": "sdist", "digests": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}],
                "1.5": [{"url": "https://example.test/1.5.tar.gz", "packagetype": "sdist", "yanked": true, "digests": {"sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}],
                "2.0": [{"url": "https://example.test/2.tar.gz", "packagetype": "sdist", "digests": {"sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}]
            }
        }"#,
    )
    .unwrap();
    let dependency = dependency("*");

    assert!(
        python_compare_versions(&dependency, "1.5", "2.0", &metadata)
            .unwrap_err()
            .to_string()
            .contains("non-yanked")
    );
    assert!(
        python_compare_versions(&dependency, "not a version", "2.0", &metadata)
            .unwrap_err()
            .to_string()
            .contains("PEP 440")
    );
    assert!(
        python_compare_versions(&dependency, "1.0", "1.0", &metadata)
            .unwrap_err()
            .to_string()
            .contains("distinct")
    );
    assert!(
        test_fetcher(usize::MAX)
            .1
            .python_range_versions(&dependency, "2.0", "1.0", &metadata)
            .unwrap_err()
            .to_string()
            .contains("must be older")
    );
}
