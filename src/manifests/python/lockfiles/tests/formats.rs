use super::*;

#[test]
fn poetry_accepts_modern_two_x_lock_schemas() {
    for version in ["2.0", "2.1", "2.42"] {
        let directory = tempdir().unwrap();
        let path = directory.path().join("poetry.lock");
        fs::write(
            &path,
            format!(
                r#"[metadata]
lock-version = "{version}"
[[package]]
name = "demo"
version = "1.2.3"
"#
            ),
        )
        .unwrap();
        let mut dependencies = vec![dependency("demo>=1")];

        enrich_poetry(&path, &mut dependencies).unwrap();

        assert_eq!(
            dependencies[0].resolved_version.as_deref(),
            Some("1.2.3"),
            "schema {version}"
        );
    }
}

#[test]
fn poetry_rejects_incompatible_or_malformed_lock_schemas() {
    for version in ["1.1", "3.0", "2", "2.", "2.1.0", "2.x", "02.1"] {
        let directory = tempdir().unwrap();
        let path = directory.path().join("poetry.lock");
        fs::write(
            &path,
            format!("[metadata]\nlock-version = \"{version}\"\npackage = []\n"),
        )
        .unwrap();
        let mut dependencies = vec![dependency("demo>=1")];

        assert!(
            enrich_poetry(&path, &mut dependencies).is_err(),
            "accepted schema {version}"
        );
        assert!(dependencies[0].resolved_version.is_none());
    }
}

#[test]
fn unsupported_or_malformed_lockfile_schemas_fail_closed() {
    let cases: &[(&str, LockEnricher, &[&str])] = &[
        (
            "poetry.lock",
            enrich_poetry,
            &[
                "package = []\n",
                "[metadata]\nlock-version = 2\npackage = []\n",
                "[metadata]\nlock-version = \"3.0\"\npackage = []\n",
            ],
        ),
        (
            "uv.lock",
            enrich_uv,
            &[
                "package = []\n",
                "version = \"1\"\npackage = []\n",
                "version = 2\npackage = []\n",
            ],
        ),
        (
            "pdm.lock",
            enrich_pdm,
            &[
                "package = []\n",
                "[metadata]\nlock_version = 4.5\npackage = []\n",
                "[metadata]\nlock_version = \"5.0.0\"\npackage = []\n",
            ],
        ),
    ];

    for (name, enrich, contents) in cases {
        for contents in *contents {
            let directory = tempdir().unwrap();
            let path = directory.path().join(name);
            fs::write(&path, contents).unwrap();
            let mut dependencies = vec![dependency("demo>=1")];

            assert!(
                enrich(&path, &mut dependencies).is_err(),
                "accepted {name}: {contents}"
            );
            assert_eq!(dependencies.len(), 1);
            assert_eq!(dependencies[0].name, "demo");
            assert!(dependencies[0].resolved_version.is_none());
        }
    }

    for contents in [
        r#"{"default":{},"develop":{}}"#,
        r#"{"_meta":{"pipfile-spec":"6"},"default":{},"develop":{}}"#,
        r#"{"_meta":{"pipfile-spec":7},"default":{},"develop":{}}"#,
    ] {
        let directory = tempdir().unwrap();
        let path = directory.path().join("Pipfile.lock");
        fs::write(&path, contents).unwrap();
        let mut dependencies = vec![dependency("demo>=1")];

        assert!(pipfile::enrich(&path, &mut dependencies).is_err());
        assert_eq!(dependencies.len(), 1);
        assert_eq!(dependencies[0].name, "demo");
        assert!(dependencies[0].resolved_version.is_none());
    }
}

#[test]
fn malformed_lock_structure_is_rejected() {
    let (_directory, path) = write_lock("poetry.lock", "package = {}\n");
    let mut dependencies = vec![dependency("demo")];
    assert!(enrich_poetry(&path, &mut dependencies).is_err());

    let (_directory, path) = write_lock("Pipfile.lock", r#"{"default":[]}"#);
    assert!(pipfile::enrich(&path, &mut dependencies).is_err());
}

#[test]
fn selects_only_constraint_compatible_same_name_record() {
    let (_directory, path) = write_lock(
        "poetry.lock",
        r#"
[[package]]
name = "demo"
version = "1.0"
files = [{file = "demo-1.0.tar.gz", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111"}]
[[package]]
name = "Demo"
version = "2.1"
files = [{file = "demo-2.1.tar.gz", hash = "sha256:2222222222222222222222222222222222222222222222222222222222222222"}]
"#,
    );
    let mut dependencies = vec![dependency("demo>=2")];
    enrich_poetry(&path, &mut dependencies).unwrap();
    assert_eq!(dependencies[0].resolved_version.as_deref(), Some("2.1"));
    assert_eq!(
        dependencies[0].integrity.as_deref(),
        Some("sha256:2222222222222222222222222222222222222222222222222222222222222222")
    );
}

#[test]
fn rejects_incompatible_or_ambiguous_same_name_records() {
    let packages: TomlValue = ::toml::from_str(
        r#"package = [
            {name = "demo", version = "1.0"},
            {name = "Demo", version = "2.0"}
        ]"#,
    )
    .unwrap();
    let packages = packages.get("package").unwrap().as_array().unwrap();
    let index = index_toml_packages(packages);
    assert!(find_package(Path::new("lock"), &index, &dependency("demo>=3")).is_err());
    assert!(find_package(Path::new("lock"), &index, &dependency("demo>=1")).is_err());
}

#[test]
fn poetry_and_pdm_expand_all_authorized_artifacts() {
    let wheel = "1".repeat(64);
    let sdist = "2".repeat(64);
    let package: TomlValue = ::toml::from_str(&format!(
        r#"
name = "demo"
version = "1"
files = [
    {{url = "https://example.test/demo-1-py3-none-any.whl", hash = "sha256:{wheel}"}},
    {{url = "https://example.test/demo-1.tar.gz", hash = "sha256:{sdist}"}}
]
"#,
    ))
    .unwrap();
    let mut dependency = dependency("demo");
    dependency.resolved_version = Some("1".into());
    let artifacts = expand_file_artifacts(Path::new("lock"), &dependency, &package).unwrap();
    assert_eq!(artifacts.len(), 2);
    assert_eq!(
        artifacts[0].integrity.as_deref(),
        Some(format!("sha256:{wheel}").as_str())
    );
    assert_eq!(
        artifacts[1].integrity.as_deref(),
        Some(format!("sha256:{sdist}").as_str())
    );
    assert_eq!(
        artifacts[0].source_url.as_deref(),
        Some("https://example.test/demo-1-py3-none-any.whl")
    );
    assert_eq!(
        artifacts[1].source_url.as_deref(),
        Some("https://example.test/demo-1.tar.gz")
    );
}

#[test]
fn multiple_unmapped_hashes_preserve_the_complete_lock_authorization_set() {
    let first = "1".repeat(64);
    let second = "2".repeat(64);
    let package: TomlValue = ::toml::from_str(&format!(
        r#"
name = "demo"
version = "1"
files = [{{hash = "sha256:{first}"}}, {{hash = "sha256:{second}"}}]
"#,
    ))
    .unwrap();
    let mut dependency = dependency("demo");
    dependency.resolved_version = Some("1".into());
    let artifacts = expand_file_artifacts(Path::new("lock"), &dependency, &package).unwrap();
    assert_eq!(artifacts.len(), 2);
    assert_eq!(
        artifacts[0].integrity.as_deref(),
        Some(format!("sha256:{first}").as_str())
    );
    assert_eq!(
        artifacts[1].integrity.as_deref(),
        Some(format!("sha256:{second}").as_str())
    );
    assert!(
        artifacts
            .iter()
            .all(|artifact| !artifact.registry_integrity_required)
    );
}

#[test]
fn uv_expands_sdist_and_wheels() {
    let (_directory, path) = write_lock(
        "uv.lock",
        r#"
[[package]]
name = "demo"
version = "1"
sdist = {url = "https://example.test/demo.tar.gz", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
wheels = [{url = "https://example.test/demo.whl", hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]
"#,
    );
    let mut dependencies = vec![dependency("demo")];
    enrich_uv(&path, &mut dependencies).unwrap();
    assert_eq!(dependencies.len(), 2);
    assert_eq!(
        dependencies[0].integrity.as_deref(),
        Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert_eq!(
        dependencies[0].source_url.as_deref(),
        Some("https://example.test/demo.tar.gz")
    );
    assert_eq!(
        dependencies[1].integrity.as_deref(),
        Some("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    );
    assert_eq!(
        dependencies[1].source_url.as_deref(),
        Some("https://example.test/demo.whl")
    );
}
