use super::*;

#[test]
fn poetry_and_pdm_do_not_resolve_hashless_direct_sources_as_registry_packages() {
    for (name, enrich) in [
        (
            "poetry.lock",
            enrich_poetry as fn(&Path, &mut Vec<Dependency>) -> crate::error::Result<()>,
        ),
        ("pdm.lock", enrich_pdm),
    ] {
        let (_directory, path) = write_lock(
            name,
            r#"
[[package]]
name = "demo"
version = "1"
url = "https://artifacts.example.test/demo.tar.gz"
"#,
        );
        let mut dependencies = vec![dependency(
            "demo @ https://artifacts.example.test/demo.tar.gz",
        )];
        enrich(&path, &mut dependencies).unwrap();

        assert!(dependencies[0].resolved_version.is_none());
        assert!(dependencies[0].integrity.is_none());
        assert!(!dependencies[0].registry_integrity_required);
        assert!(!dependencies[0].is_resolved());
    }
}

#[test]
fn poetry_and_pdm_preserve_pinned_github_resolution_without_artifact_hashes() {
    let revision = "0123456789abcdef0123456789abcdef01234567";
    for (name, enrich) in [
        (
            "poetry.lock",
            enrich_poetry as fn(&Path, &mut Vec<Dependency>) -> crate::error::Result<()>,
        ),
        ("pdm.lock", enrich_pdm),
    ] {
        let (_directory, path) = write_lock(
            name,
            r#"
[[package]]
name = "demo"
version = "1"
source = {type = "git", url = "https://github.com/acme/demo.git", resolved_reference = "0123456789abcdef0123456789abcdef01234567"}
"#,
        );
        let mut dependency = dependency("demo");
        dependency.resolved_version = Some(revision.to_owned());
        dependency.source_url = Some(format!(
            "https://codeload.github.com/acme/demo/tar.gz/{revision}"
        ));
        let mut dependencies = vec![dependency];
        enrich(&path, &mut dependencies).unwrap();

        assert_eq!(dependencies[0].resolved_version.as_deref(), Some(revision));
        assert!(dependencies[0].is_pinned_github());
        assert!(dependencies[0].is_resolved());
        assert!(!dependencies[0].registry_integrity_required);
    }
}

#[test]
fn uv_preserves_pinned_github_resolution() {
    let revision = "0123456789abcdef0123456789abcdef01234567";
    let digest = "a".repeat(64);
    let (_directory, path) = write_lock(
        "uv.lock",
        &format!(
            r#"
[[package]]
name = "demo"
version = "9.9.9"
sdist = {{url = "https://artifacts.example.test/demo.tar.gz", hash = "sha256:{digest}"}}
"#
        ),
    );
    let mut dependency = dependency("demo");
    dependency.resolved_version = Some(revision.to_owned());
    dependency.source_url = Some(format!(
        "https://codeload.github.com/acme/demo/tar.gz/{revision}"
    ));
    let mut dependencies = vec![dependency];

    enrich_uv(&path, &mut dependencies).unwrap();

    assert_eq!(dependencies[0].resolved_version.as_deref(), Some(revision));
    assert!(dependencies[0].is_pinned_github());
    assert!(dependencies[0].integrity.is_none());
}

#[test]
fn direct_source_lock_artifact_requires_and_accepts_sha256() {
    let digest = "a".repeat(64);
    let (_directory, path) = write_lock(
        "poetry.lock",
        &format!(
            r#"
[[package]]
name = "demo"
version = "1"
url = "https://artifacts.example.test/demo.tar.gz"
files = [{{file = "demo.tar.gz", hash = "sha256:{digest}"}}]
"#
        ),
    );
    let mut dependencies = vec![dependency(
        "demo @ https://artifacts.example.test/demo.tar.gz",
    )];
    enrich_poetry(&path, &mut dependencies).unwrap();

    assert_eq!(dependencies[0].resolved_version.as_deref(), Some("1"));
    assert_eq!(
        dependencies[0].integrity.as_deref(),
        Some(format!("sha256:{digest}").as_str())
    );
    assert!(dependencies[0].is_resolved());
}

#[test]
fn poetry_and_pdm_reject_every_malformed_selected_hash() {
    for (name, enrich) in [
        (
            "poetry.lock",
            enrich_poetry as fn(&Path, &mut Vec<Dependency>) -> crate::error::Result<()>,
        ),
        ("pdm.lock", enrich_pdm),
    ] {
        let (_directory, path) = write_lock(
            name,
            r#"
[[package]]
name = "demo"
version = "1"
files = [{file = "demo-1.tar.gz", hash = "sha256:not-a-digest"}]
"#,
        );
        let mut dependencies = vec![dependency("demo")];
        assert!(enrich(&path, &mut dependencies).is_err());
    }
}

#[test]
fn uv_direct_sources_cannot_be_redirected_by_unrelated_artifacts() {
    let digest = "a".repeat(64);
    for requirement in [
        "demo @ https://sources.example.test/demo.tar.gz",
        "demo @ git+https://git.example.test/demo.git@0123456789abcdef0123456789abcdef01234567",
        "demo @ file:../demo",
    ] {
        let (_directory, path) = write_lock(
            "uv.lock",
            &format!(
                r#"
[[package]]
name = "demo"
version = "9.9.9"
url = "{source}"
sdist = {{url = "https://attacker.example.test/demo.tar.gz", hash = "sha256:{digest}"}}
"#,
                source = dependency(requirement)
                    .source_url
                    .unwrap_or_else(|| requirement.to_owned())
            ),
        );
        let mut dependencies = vec![dependency(requirement)];
        let source_url = dependencies[0].source_url.clone();

        enrich_uv(&path, &mut dependencies).unwrap();

        assert_eq!(dependencies.len(), 1);
        assert_eq!(dependencies[0].source_url, source_url);
        assert!(dependencies[0].resolved_version.is_none());
        assert!(dependencies[0].integrity.is_none());
        assert!(!dependencies[0].registry_integrity_required);
    }
}

#[test]
fn uv_direct_url_accepts_only_identity_matching_artifact_hashes() {
    let source = "https://sources.example.test/demo.tar.gz";
    let matching = "a".repeat(64);
    let unrelated = "b".repeat(64);
    let (_directory, path) = write_lock(
        "uv.lock",
        &format!(
            r#"
[[package]]
name = "demo"
version = "1.2.3"
url = "{source}"
sdist = {{url = "{source}", hash = "sha256:{matching}"}}
wheels = [{{url = "https://attacker.example.test/demo.whl", hash = "sha256:{unrelated}"}}]
"#
        ),
    );
    let mut dependencies = vec![dependency(&format!("demo @ {source}"))];

    enrich_uv(&path, &mut dependencies).unwrap();

    assert_eq!(dependencies.len(), 1);
    assert_eq!(dependencies[0].source_url.as_deref(), Some(source));
    assert_eq!(dependencies[0].resolved_version.as_deref(), Some("1.2.3"));
    assert_eq!(
        dependencies[0].integrity.as_deref(),
        Some(format!("sha256:{matching}").as_str())
    );
    assert!(dependencies[0].is_resolved());
}

#[test]
fn uv_rejects_malformed_artifact_hashes() {
    let (_directory, path) = write_lock(
        "uv.lock",
        r#"
[[package]]
name = "demo"
version = "1"
sdist = {url = "https://example.test/demo.tar.gz", hash = "sha256:not-a-digest"}
"#,
    );
    let mut dependencies = vec![dependency("demo")];
    assert!(enrich_uv(&path, &mut dependencies).is_err());
}
