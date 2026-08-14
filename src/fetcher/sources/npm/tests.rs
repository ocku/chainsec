use super::*;
use crate::fetcher::FetchPolicy;
use base64::Engine as _;

fn integrity(algorithm: &str, bytes: usize) -> String {
    format!(
        "{algorithm}-{}",
        base64::engine::general_purpose::STANDARD.encode(vec![0_u8; bytes])
    )
}

fn dependency(requirement: &str) -> Dependency {
    Dependency::declared(Ecosystem::Npm, "example", requirement)
}

fn test_fetcher(max_packages: usize) -> (tempfile::TempDir, SourceFetcher) {
    let temporary = tempfile::tempdir().unwrap();
    let limits = crate::model::EngineLimits {
        max_packages,
        ..crate::model::EngineLimits::default()
    };
    let fetcher = SourceFetcher::new(
        temporary.path().join("cache"),
        FetchPolicy::default(),
        limits,
    )
    .unwrap();
    (temporary, fetcher)
}

#[tokio::test]
async fn uses_the_locked_npm_tarball_url_without_requesting_registry_metadata() {
    let temporary = tempfile::tempdir().unwrap();
    let fetcher = SourceFetcher::new(
        temporary.path().join("cache"),
        FetchPolicy::default(),
        crate::model::EngineLimits::default(),
    )
    .unwrap();
    let mut dependency = dependency("npm:example@1.0.0");
    dependency.resolved_version = Some("1.0.0".to_owned());
    dependency.source_url = Some("https://artifacts.example.test/npm/example-1.0.0.tgz".to_owned());

    let mut budget = fetcher.network_budget();
    let (url, _) = fetcher
        .npm_artifact_request_with_budget(&dependency, &mut budget)
        .await
        .unwrap();

    assert_eq!(
        url.as_str(),
        "https://artifacts.example.test/npm/example-1.0.0.tgz"
    );
}

#[test]
fn rejects_an_invalid_locked_npm_tarball_url() {
    let mut dependency = dependency("npm:example@1.0.0");
    dependency.source_url = Some("not a URL".to_owned());

    let error = locked_npm_artifact_url(&dependency).unwrap_err();

    assert!(error.to_string().contains("invalid locked npm tarball URL"));
}

#[test]
fn returns_selected_and_older_pullable_npm_versions_in_semantic_order() {
    let metadata = serde_json::json!({
        "dist-tags": { "latest": "2.0.0" },
        "versions": {
            "10.0.0": { "dist": { "tarball": "https://example.test/10.tgz", "integrity": integrity("sha512", 64) } },
            "2.0.0": { "dist": { "tarball": "https://example.test/2.tgz", "integrity": integrity("sha512", 64) } },
            "1.10.0": { "dist": { "tarball": "https://example.test/1.10.tgz", "integrity": "md5-unsupported" } },
            "1.9.0": { "dist": { "tarball": "https://example.test/1.9.tgz", "integrity": integrity("sha256", 32) } },
            "1.2.0": { "dist": { "integrity": integrity("sha512", 64) } },
            "1.1.0": { "dist": { "tarball": "https://example.test/1.1.tgz", "integrity": integrity("sha512", 64) } }
        }
    });
    let dependency = dependency("npm:example@latest");

    assert_eq!(
        test_fetcher(usize::MAX)
            .1
            .npm_versions_at_or_below(
                &dependency,
                select_npm_release(&dependency, "latest", &metadata).unwrap(),
                1,
                &metadata,
            )
            .unwrap()
            .len(),
        1
    );
    let selected = select_npm_release(&dependency, "latest", &metadata).unwrap();
    let error = test_fetcher(2)
        .1
        .npm_versions_at_or_below(&dependency, selected.clone(), 3, &metadata)
        .unwrap_err();
    assert_eq!(error.code(), "limit_exceeded");
    assert!(error.to_string().contains("remote version candidates"));

    let versions = test_fetcher(usize::MAX)
        .1
        .npm_versions_at_or_below(&dependency, selected, 3, &metadata)
        .unwrap();

    assert_eq!(
        versions
            .iter()
            .map(|dependency| dependency.resolved_version.as_deref().unwrap())
            .collect::<Vec<_>>(),
        ["2.0.0", "1.9.0", "1.1.0"]
    );
    assert!(versions.iter().all(Dependency::is_resolved));
    assert!(
        versions
            .iter()
            .all(|dependency| dependency.source_url.is_some())
    );
}

#[test]
fn skips_an_unpullable_selected_npm_version() {
    let metadata = serde_json::json!({
        "dist-tags": { "latest": "3.0.0" },
        "versions": {
            "3.0.0": { "dist": { "tarball": "https://example.test/3.tgz", "integrity": "md5-unsupported" } },
            "2.0.0": { "dist": { "tarball": "https://example.test/2.tgz", "integrity": integrity("sha512", 64) } },
            "1.0.0": { "dist": { "tarball": "https://example.test/1.tgz", "integrity": integrity("sha256", 32) } }
        }
    });
    let dependency = dependency("npm:example@latest");
    let selected = select_npm_release(&dependency, "latest", &metadata).unwrap();

    let versions = test_fetcher(usize::MAX)
        .1
        .npm_versions_at_or_below(&dependency, selected, 2, &metadata)
        .unwrap();

    assert_eq!(
        versions
            .iter()
            .map(|dependency| dependency.resolved_version.as_deref().unwrap())
            .collect::<Vec<_>>(),
        ["2.0.0", "1.0.0"]
    );
}

#[test]
fn selects_a_valid_npm_release_regardless_of_nonstandard_yanked_metadata() {
    let metadata = serde_json::json!({
        "versions": {
            "1.6.0": { "yanked": true, "dist": { "tarball": "https://example.test/1.6.tgz", "integrity": integrity("sha512", 64) } },
            "1.5.0": { "dist": { "tarball": "https://example.test/1.5.tgz", "integrity": integrity("sha512", 64) } },
            "1.0.0": { "dist": { "tarball": "https://example.test/1.tgz", "integrity": integrity("sha512", 64) } }
        }
    });
    let dependency = dependency("^1.0.0");

    let (version, _) = select_npm_release(&dependency, "^1.0.0", &metadata).unwrap();

    assert_eq!(version, "1.6.0");
}

#[test]
fn unlocked_range_selects_next_highest_pullable_npm_release() {
    let metadata = serde_json::json!({
        "versions": {
            "1.4.0": { "dist": { "tarball": "https://example.test/1.4.tgz" } },
            "1.3.0": { "dist": { "integrity": integrity("sha512", 64) } },
            "1.2.0": { "dist": { "tarball": "https://example.test/1.2.tgz", "integrity": integrity("sha256", 32) } }
        }
    });
    let mut dependency = dependency("^1.0.0");

    resolve_npm_release(&mut dependency, "^1.0.0".to_owned(), &metadata).unwrap();

    assert_eq!(dependency.resolved_version.as_deref(), Some("1.2.0"));
    assert_eq!(
        dependency.source_url.as_deref(),
        Some("https://example.test/1.2.tgz")
    );
}

#[test]
fn rejects_documented_non_registry_specifiers_without_treating_them_as_dist_tags() {
    let dependency = dependency("*");

    let error = validate_npm_registry_requirement(&dependency, "https://example.test/example.tgz")
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("tarball dependencies require a lockfile integrity pin")
    );

    for requirement in [
        "git+https://example.test/owner/repository.git#main",
        "git@github.com:owner/repository.git#main",
        "github:owner/repository#main",
        "owner/repository#main",
    ] {
        let error = validate_npm_registry_requirement(&dependency, requirement).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Git dependencies require a lockfile-resolved immutable source")
        );
    }
}

#[test]
fn includes_valid_npm_versions_with_nonstandard_yanked_metadata_in_last_selection() {
    let metadata = serde_json::json!({
        "versions": {
            "3.0.0": { "dist": { "tarball": "https://example.test/3.tgz", "integrity": integrity("sha512", 64) } },
            "2.0.0": { "yanked": true, "dist": { "tarball": "https://example.test/2.tgz", "integrity": integrity("sha512", 64) } },
            "1.0.0": { "dist": { "tarball": "https://example.test/1.tgz", "integrity": integrity("sha512", 64) } },
            "0.5.0": { "dist": { "tarball": "https://example.test/0.5.tgz", "integrity": integrity("sha512", 64) } }
        }
    });
    let dependency = dependency("*");
    let selected = select_npm_release(&dependency, "3.0.0", &metadata).unwrap();

    let versions = test_fetcher(usize::MAX)
        .1
        .npm_versions_at_or_below(&dependency, selected, 3, &metadata)
        .unwrap();

    assert_eq!(
        versions
            .iter()
            .map(|dependency| dependency.resolved_version.as_deref().unwrap())
            .collect::<Vec<_>>(),
        ["3.0.0", "2.0.0", "1.0.0"]
    );
}

#[test]
fn permits_a_dist_tag_that_targets_a_valid_release_with_nonstandard_yanked_metadata() {
    let metadata = serde_json::json!({
        "dist-tags": { "latest": "3.0.0" },
        "versions": {
            "3.0.0": { "yanked": true, "dist": { "tarball": "https://example.test/3.tgz", "integrity": integrity("sha512", 64) } }
        }
    });
    let dependency = dependency("npm:example@latest");

    let (version, _) = select_npm_release(&dependency, "latest", &metadata).unwrap();

    assert_eq!(version, "3.0.0");
}

#[test]
fn rejects_a_dist_tag_that_targets_an_unpullable_npm_release() {
    let metadata = serde_json::json!({
        "dist-tags": { "latest": "3.0.0" },
        "versions": {
            "3.0.0": { "dist": { "tarball": "https://example.test/3.tgz", "integrity": "md5-unsupported" } },
            "2.0.0": { "dist": { "tarball": "https://example.test/2.tgz", "integrity": integrity("sha512", 64) } }
        }
    });
    let mut dependency = dependency("npm:example@latest");

    let error = resolve_npm_release(&mut dependency, "latest".to_owned(), &metadata).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("npm release 3.0.0 has no supported SHA-256 or SHA-512 integrity")
    );
    assert!(!dependency.is_resolved());
}

#[test]
fn unlocked_npm_and_deno_npm_resolution_use_valid_releases_with_nonstandard_yanked_metadata() {
    let metadata = serde_json::json!({
        "versions": {
            "1.1.0": { "yanked": true, "dist": { "tarball": "https://example.test/1.1.tgz", "integrity": integrity("sha512", 64) } },
            "1.0.0": { "dist": { "tarball": "https://example.test/1.tgz", "integrity": integrity("sha512", 64) } }
        }
    });

    let mut npm = dependency("^1.0.0");
    resolve_npm_release(&mut npm, "^1.0.0".to_owned(), &metadata).unwrap();
    assert_eq!(npm.resolved_version.as_deref(), Some("1.1.0"));

    let mut deno = Dependency::declared(Ecosystem::Deno, "example", "npm:example@^1.0.0");
    let (_, requirement) = npm_package_and_requirement(&deno);
    resolve_npm_release(&mut deno, requirement, &metadata).unwrap();
    assert_eq!(deno.resolved_version.as_deref(), Some("1.1.0"));
}

#[test]
fn pins_a_valid_npm_release_with_nonstandard_yanked_metadata() {
    let release = serde_json::json!({
        "yanked": true,
        "dist": { "tarball": "https://example.test/1.tgz", "integrity": integrity("sha512", 64) }
    });
    let mut dependency = dependency("1.0.0");

    pin_npm_release(&mut dependency, "1.0.0".to_owned(), &release).unwrap();

    assert_eq!(dependency.resolved_version.as_deref(), Some("1.0.0"));
    assert!(dependency.is_resolved());
}

#[test]
fn compares_exact_pullable_npm_endpoints_in_to_from_order() {
    let metadata = serde_json::json!({
        "versions": {
            "1.0.0": { "dist": { "tarball": "https://example.test/1.tgz", "integrity": integrity("sha512", 64) } },
            "1.5.0": { "dist": { "tarball": "https://example.test/1.5.tgz", "integrity": integrity("sha512", 64) } },
            "2.0.0": { "dist": { "tarball": "https://example.test/2.tgz", "integrity": integrity("sha512", 64) } }
        }
    });

    let versions = npm_compare_versions(&dependency("*"), "1.0.0", "2.0.0", &metadata).unwrap();

    assert_eq!(
        versions
            .iter()
            .map(|dependency| dependency.resolved_version.as_deref().unwrap())
            .collect::<Vec<_>>(),
        ["2.0.0", "1.0.0"]
    );
}

#[test]
fn ranges_include_endpoints_and_skip_unpullable_npm_intermediates() {
    let metadata = serde_json::json!({
        "versions": {
            "0.9.0": { "dist": { "tarball": "https://example.test/0.9.tgz", "integrity": integrity("sha512", 64) } },
            "1.0.0": { "dist": { "tarball": "https://example.test/1.tgz", "integrity": integrity("sha512", 64) } },
            "1.4.0": { "yanked": true, "dist": { "tarball": "https://example.test/1.4.tgz", "integrity": integrity("sha512", 64) } },
            "1.5.0": { "dist": { "tarball": "https://example.test/1.5.tgz", "integrity": "md5-unsupported" } },
            "1.6.0": { "dist": { "tarball": "https://example.test/1.6.tgz", "integrity": integrity("sha256", 32) } },
            "2.0.0": { "dist": { "tarball": "https://example.test/2.tgz", "integrity": integrity("sha512", 64) } },
            "3.0.0": { "dist": { "tarball": "https://example.test/3.tgz", "integrity": integrity("sha512", 64) } }
        }
    });

    let error = test_fetcher(2)
        .1
        .npm_range_versions(&dependency("*"), "1.0.0", "2.0.0", &metadata)
        .unwrap_err();
    assert_eq!(error.code(), "limit_exceeded");
    assert!(error.to_string().contains("remote version candidates"));

    let versions = test_fetcher(usize::MAX)
        .1
        .npm_range_versions(&dependency("*"), "1.0.0", "2.0.0", &metadata)
        .unwrap();

    assert_eq!(
        versions
            .iter()
            .map(|dependency| dependency.resolved_version.as_deref().unwrap())
            .collect::<Vec<_>>(),
        ["2.0.0", "1.6.0", "1.4.0", "1.0.0"]
    );
}

#[test]
fn rejects_missing_equal_and_reversed_npm_endpoints() {
    let metadata = serde_json::json!({
        "versions": {
            "1.0.0": { "dist": { "tarball": "https://example.test/1.tgz", "integrity": integrity("sha512", 64) } },
            "2.0.0": { "dist": { "tarball": "https://example.test/2.tgz", "integrity": integrity("sha512", 64) } }
        }
    });
    let dependency = dependency("*");

    assert!(
        npm_compare_versions(&dependency, "0.5.0", "2.0.0", &metadata)
            .unwrap_err()
            .to_string()
            .contains("not published")
    );
    assert!(
        npm_compare_versions(&dependency, "invalid", "2.0.0", &metadata)
            .unwrap_err()
            .to_string()
            .contains("semantic version")
    );
    assert!(
        npm_compare_versions(&dependency, "1.0.0", "1.0.0", &metadata)
            .unwrap_err()
            .to_string()
            .contains("distinct")
    );
    assert!(
        test_fetcher(usize::MAX)
            .1
            .npm_range_versions(&dependency, "2.0.0", "1.0.0", &metadata)
            .unwrap_err()
            .to_string()
            .contains("must be older")
    );
}
