use std::{fs, path::Path};

use ::toml::Value as TomlValue;
use tempfile::tempdir;

use super::{
    artifact::expand_file_artifacts,
    enrich, pipfile,
    toml::{enrich_pdm, enrich_poetry, enrich_uv},
};
use crate::{
    manifests::{
        python::{
            declarations::dependency_from_requirement,
            matching::{find_package, index_toml_packages},
        },
        shared::{ManifestRoot, with_manifest_roots},
    },
    model::Dependency,
};

fn dependency(requirement: &str) -> Dependency {
    dependency_from_requirement(requirement)
}

fn write_lock(name: &str, contents: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempdir().unwrap();
    let path = directory.path().join(name);
    let contents = match name {
        "poetry.lock" => format!("[metadata]\nlock-version = \"2.0\"\n{contents}"),
        "uv.lock" => format!("version = 1\n{contents}"),
        "pdm.lock" => format!("[metadata]\nlock_version = \"4.5.0\"\n{contents}"),
        "Pipfile.lock" => {
            let mut value: serde_json::Value = serde_json::from_str(contents).unwrap();
            value
                .as_object_mut()
                .unwrap()
                .insert("_meta".into(), serde_json::json!({"pipfile-spec": 6}));
            serde_json::to_string(&value).unwrap()
        }
        _ => contents.to_owned(),
    };
    fs::write(&path, contents).unwrap();
    (directory, path)
}

#[test]
fn pipfile_matching_uses_canonical_names() {
    let (_directory, path) = write_lock(
        "Pipfile.lock",
        &format!(
            r#"{{"default":{{"my-package":{{"version":"==1.2.3","hashes":["sha256:{}"]}}}},"develop":{{}}}}"#,
            "a".repeat(64)
        ),
    );
    let mut dependencies = vec![dependency("My__Package>=1")];
    pipfile::enrich(&path, &mut dependencies).unwrap();
    assert_eq!(dependencies[0].resolved_version.as_deref(), Some("1.2.3"));
    assert_eq!(
        dependencies[0].integrity.as_deref(),
        Some(format!("sha256:{}", "a".repeat(64)).as_str())
    );
}

#[test]
fn pipfile_deduplicates_identical_default_and_develop_records() {
    let hash = format!("sha256:{}", "a".repeat(64));
    let (_directory, path) = write_lock(
        "Pipfile.lock",
        &format!(
            r#"{{"default":{{"demo":{{"version":"==1.2.3","hashes":["{hash}"]}}}},"develop":{{"demo":{{"version":"==1.2.3","hashes":["{hash}"]}}}}}}"#
        ),
    );
    let mut dependencies = vec![dependency("demo>=1")];

    pipfile::enrich(&path, &mut dependencies).unwrap();

    assert_eq!(dependencies[0].resolved_version.as_deref(), Some("1.2.3"));
    assert_eq!(dependencies[0].integrity.as_deref(), Some(hash.as_str()));
}

#[test]
fn pipfile_indexes_large_normalized_name_collision_buckets() {
    let separators = ['-', '_', '.'];
    let mut entries = serde_json::Map::new();
    let mut first_name = String::new();
    for index in 0..1_000usize {
        let mut variant = index;
        let mut name = String::new();
        for (position, character) in "collision".chars().enumerate() {
            name.push(character);
            if position < "collision".len() - 1 {
                name.push(separators[variant % separators.len()]);
                variant /= separators.len();
            }
        }
        if index == 0 {
            first_name.clone_from(&name);
        }
        entries.insert(name, serde_json::json!({"version": format!("=={index}")}));
    }
    let contents = serde_json::json!({"default": entries, "develop": {}}).to_string();
    let (_directory, path) = write_lock("Pipfile.lock", &contents);
    let mut dependencies = vec![dependency(&format!("{first_name}>=10000"))];

    let error = pipfile::enrich(&path, &mut dependencies).unwrap_err();

    assert!(error.to_string().contains("no lock record"));
}

#[cfg(unix)]
#[test]
fn lock_selection_uses_the_opened_root_after_path_replacement() {
    let parent = tempdir().unwrap();
    let root_path = parent.path().join("root");
    fs::create_dir(&root_path).unwrap();
    fs::write(
        root_path.join("poetry.lock"),
        "[metadata]\nlock-version = \"2.0\"\n[[package]]\nname = \"trusted\"\nversion = \"1\"\n",
    )
    .unwrap();
    let root = ManifestRoot::open(&root_path).unwrap();

    fs::rename(&root_path, parent.path().join("original")).unwrap();
    fs::create_dir(&root_path).unwrap();
    fs::write(root_path.join("poetry.lock"), "package = {}").unwrap();

    let mut dependencies = Vec::new();
    let mut lockfiles = Vec::new();
    let contexts = with_manifest_roots(std::slice::from_ref(&root), || {
        enrich(
            &root,
            &mut dependencies,
            &mut lockfiles,
            &[],
            crate::model::EngineLimits::default().max_packages,
        )
    })
    .unwrap()
    .unwrap();

    assert_eq!(contexts.len(), 1);
    assert_eq!(lockfiles, vec![root_path.join("poetry.lock")]);
}

type LockEnricher = fn(&Path, &mut Vec<Dependency>) -> crate::error::Result<()>;

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
fn malformed_unconstrained_pipfile_version_is_rejected() {
    let (_directory, path) = write_lock(
        "Pipfile.lock",
        r#"{"default":{"demo":{"version":"not-a-version"}},"develop":{}}"#,
    );
    let mut dependencies = vec![dependency("demo")];

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
fn pipfile_does_not_resolve_hashless_direct_url_or_vcs_dependencies() {
    for requirement in [
        "demo @ https://artifacts.example.test/demo.tar.gz",
        "demo @ git+https://git.example.test/demo.git@0123456789abcdef0123456789abcdef01234567",
    ] {
        let source = requirement.split_once('@').unwrap().1.trim();
        let (_directory, path) = write_lock(
            "Pipfile.lock",
            &format!(
                r#"{{"default":{{"demo":{{"version":"==1","file":"{source}"}}}},"develop":{{}}}}"#
            ),
        );
        let mut dependencies = vec![dependency(requirement)];
        pipfile::enrich(&path, &mut dependencies).unwrap();

        assert!(dependencies[0].resolved_version.is_none());
        assert!(dependencies[0].integrity.is_none());
        assert!(!dependencies[0].registry_integrity_required);
        assert!(!dependencies[0].is_resolved());
    }
}

#[test]
fn pipfile_expands_multiple_authorized_hashes() {
    let first = "1".repeat(64);
    let second = "2".repeat(64);
    let (_directory, path) = write_lock(
        "Pipfile.lock",
        &format!(
            r#"{{"default":{{"demo":{{"version":"==1","hashes":["sha256:{first}","sha256:{second}"]}}}},"develop":{{}}}}"#
        ),
    );
    let mut dependencies = vec![dependency("demo==1")];
    pipfile::enrich(&path, &mut dependencies).unwrap();
    assert_eq!(dependencies.len(), 2);
    assert_eq!(
        dependencies[0].integrity.as_deref(),
        Some(format!("sha256:{first}").as_str())
    );
    assert_eq!(
        dependencies[1].integrity.as_deref(),
        Some(format!("sha256:{second}").as_str())
    );
}

#[test]
fn pipfile_empty_hashes_require_registry_integrity() {
    let (_directory, path) = write_lock(
        "Pipfile.lock",
        r#"{"default":{"demo":{"version":"==1","hashes":[]}},"develop":{}}"#,
    );
    let mut dependencies = vec![dependency("demo==1")];
    pipfile::enrich(&path, &mut dependencies).unwrap();
    assert!(dependencies[0].requires_registry_integrity());
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
