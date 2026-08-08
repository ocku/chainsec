use std::path::Path;

use chainsec::{manifests, model::Ecosystem};

#[test]
fn npm_lockfile_enriches_resolved_artifacts() {
    let root = Path::new("tests/fixtures/manifests/npm");
    let discovery = manifests::discover(root).unwrap();
    assert_eq!(discovery.dependencies.len(), 4);
    let left_pad = discovery
        .dependencies
        .iter()
        .find(|dependency| dependency.name == "left-pad")
        .unwrap();
    assert_eq!(left_pad.ecosystem, Ecosystem::Npm);
    assert_eq!(left_pad.resolved_version.as_deref(), Some("1.3.0"));
    assert_eq!(left_pad.integrity.as_deref(), Some("sha512-fixture"));
    assert!(
        left_pad
            .source_url
            .as_deref()
            .unwrap()
            .starts_with("https://registry.npmjs.org/")
    );
    assert!(
        !discovery
            .dependencies
            .iter()
            .any(|dependency| dependency.name == "typescript")
    );
}

#[test]
fn poetry_and_deno_locks_are_detected() {
    let python = manifests::discover(Path::new("tests/fixtures/manifests/python")).unwrap();
    let httpx = python
        .dependencies
        .iter()
        .find(|dependency| dependency.name == "httpx")
        .unwrap();
    assert_eq!(httpx.resolved_version.as_deref(), Some("0.27.2"));
    assert!(httpx.integrity.as_deref().unwrap().starts_with("sha256:"));

    let deno = manifests::discover(Path::new("tests/fixtures/manifests/deno")).unwrap();
    let remote = deno
        .dependencies
        .iter()
        .find(|dependency| dependency.requirement.starts_with("https://deno.land/"))
        .unwrap();
    assert_eq!(
        remote.integrity.as_deref(),
        Some("fixture-remote-integrity")
    );
    let chalk = deno
        .dependencies
        .iter()
        .find(|dependency| dependency.requirement.starts_with("npm:"))
        .unwrap();
    assert_eq!(chalk.resolved_version.as_deref(), Some("5.3.0"));
}

#[test]
fn uv_lock_enriches_resolved_artifacts() {
    let discovery = manifests::discover(Path::new("tests/fixtures/manifests/uv")).unwrap();
    let httpx = discovery
        .dependencies
        .iter()
        .find(|dependency| dependency.name == "httpx")
        .unwrap();

    assert_eq!(httpx.resolved_version.as_deref(), Some("0.27.2"));
    assert_eq!(httpx.integrity.as_deref(), Some("sha256:uv-fixture"));
    assert_eq!(
        httpx.source_url.as_deref(),
        Some("https://files.pythonhosted.org/packages/httpx-0.27.2.tar.gz")
    );
    assert!(
        httpx
            .lockfile
            .as_deref()
            .is_some_and(|path| path.ends_with("uv.lock"))
    );
}

#[test]
fn pdm_lock_enriches_resolved_artifacts() {
    let discovery = manifests::discover(Path::new("tests/fixtures/manifests/pdm")).unwrap();
    let httpx = discovery
        .dependencies
        .iter()
        .find(|dependency| dependency.name == "httpx")
        .unwrap();

    assert_eq!(httpx.resolved_version.as_deref(), Some("0.27.2"));
    assert_eq!(httpx.integrity.as_deref(), Some("sha256:pdm-fixture"));
    assert!(
        httpx
            .lockfile
            .as_deref()
            .is_some_and(|path| path.ends_with("pdm.lock"))
    );
}

#[test]
fn yarn_and_pnpm_locks_enrich_exact_artifacts() {
    let yarn = manifests::discover(Path::new("tests/fixtures/manifests/yarn")).unwrap();
    let left_pad = &yarn.dependencies[0];
    assert_eq!(left_pad.resolved_version.as_deref(), Some("1.3.0"));
    assert_eq!(
        left_pad.source_url.as_deref(),
        Some("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz")
    );
    assert!(left_pad.is_resolved());

    let pnpm = manifests::discover(Path::new("tests/fixtures/manifests/pnpm")).unwrap();
    let left_pad = pnpm
        .dependencies
        .iter()
        .find(|dependency| dependency.name == "left-pad")
        .unwrap();
    assert_eq!(left_pad.resolved_version.as_deref(), Some("1.3.0"));
    assert_eq!(
        left_pad.source_url.as_deref(),
        Some("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz")
    );
    let scoped = pnpm
        .dependencies
        .iter()
        .find(|dependency| dependency.name == "@scope/pkg")
        .unwrap();
    assert_eq!(scoped.resolved_version.as_deref(), Some("2.0.1"));
    assert_eq!(
        scoped.source_url.as_deref(),
        Some("https://registry.example.test/@scope/pkg/-/pkg-2.0.1.tgz")
    );
}

#[test]
fn jsr_and_git_dependencies_have_immutable_acquisition_sources() {
    let jsr = manifests::discover(Path::new("tests/fixtures/manifests/jsr")).unwrap();
    let dependency = &jsr.dependencies[0];
    assert_eq!(dependency.resolved_version.as_deref(), Some("1.0.13"));
    assert_eq!(
        dependency.source_url.as_deref(),
        Some("https://jsr.io/@std/assert/1.0.13_meta.json")
    );
    assert!(dependency.is_resolved());

    let git = manifests::discover(Path::new("tests/fixtures/manifests/git")).unwrap();
    let dependency = git
        .dependencies
        .iter()
        .find(|dependency| dependency.name == "fixture")
        .unwrap();
    assert_eq!(
        dependency.resolved_version.as_deref(),
        Some("0123456789abcdef0123456789abcdef01234567")
    );
    assert_eq!(
        dependency.source_url.as_deref(),
        Some(
            "https://codeload.github.com/example/fixture/tar.gz/0123456789abcdef0123456789abcdef01234567"
        )
    );
    assert!(dependency.is_pinned_github());
    let python = git
        .dependencies
        .iter()
        .find(|dependency| dependency.name == "fixture-python")
        .unwrap();
    assert_eq!(
        python.source_url.as_deref(),
        Some(
            "https://codeload.github.com/example/fixture-python/tar.gz/89abcdef0123456789abcdef0123456789abcdef"
        )
    );
    assert!(python.is_pinned_github());
}

#[test]
fn install_scripts_are_detected_for_npm_and_python_projects() {
    let npm = tempfile::tempdir().unwrap();
    std::fs::write(
        npm.path().join("package.json"),
        r#"{"name":"fixture","scripts":{"postinstall":"node setup.js"}}"#,
    )
    .unwrap();
    let npm_discovery = manifests::discover(npm.path()).unwrap();
    assert_eq!(npm_discovery.install_scripts.len(), 1);
    assert_eq!(npm_discovery.install_scripts[0].scripts, ["postinstall"]);

    let python = tempfile::tempdir().unwrap();
    std::fs::write(python.path().join("setup.py"), "print('install')\n").unwrap();
    let python_discovery = manifests::discover(python.path()).unwrap();
    assert_eq!(python_discovery.install_scripts.len(), 1);
    assert_eq!(python_discovery.install_scripts[0].scripts, ["setup.py"]);
}

#[test]
fn malformed_manifests_are_actionable_errors() {
    let error = manifests::discover(Path::new("tests/fixtures/manifests/malformed")).unwrap_err();
    assert_eq!(error.code(), "manifest_error");
    assert!(error.to_string().contains("pyproject.toml"));
}

#[test]
fn malformed_deno_entry_types_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("deno.json"),
        r#"{"imports":{"broken":{"not":"a specifier"}}}"#,
    )
    .unwrap();

    let error = manifests::discover(root.path()).unwrap_err();
    assert_eq!(error.code(), "manifest_error");
    assert!(
        error
            .to_string()
            .contains("Deno manifest entry broken must be a string")
    );
}

#[test]
fn malformed_python_dependency_entry_types_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("pyproject.toml"),
        "[project]\ndependencies = [123]\n",
    )
    .unwrap();

    let error = manifests::discover(root.path()).unwrap_err();
    assert_eq!(error.code(), "manifest_error");
    assert!(
        error
            .to_string()
            .contains("Python project.dependencies entry 0 must be a string")
    );
}
