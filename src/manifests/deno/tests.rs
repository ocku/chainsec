use std::{fs, path::Path};

use serde_json::{Value as JsonValue, json};
use tempfile::tempdir;

use super::{
    LockfileSelection, enrich,
    jsonc::strip_jsonc,
    lockfile::{LockVersion, enrich_dependency, validate_lockfile_version},
    parse, select_manifest,
};
use crate::{
    manifests::shared::{ManifestRoot, with_manifest_roots},
    model::{Dependency, Ecosystem},
};

fn dependency(requirement: &str) -> Dependency {
    Dependency::declared(Ecosystem::Deno, "fixture", requirement)
}

fn parse_manifest(root: &Path) -> super::ParsedDeno {
    parse(root, &root.join("deno.json")).unwrap()
}

#[test]
fn jsonc_handles_comments_strings_trailing_commas_and_line_endings() {
    let input = concat!(
        "{\r\n",
        "  // CRLF comment\r\n",
        "  \"url\": \"https://example.test/a/*literal*///b\",\r",
        "  \"items\": [1, 2, /* block\r\n comment */], // CR comment\r",
        "}\r\n",
    );
    let clean = strip_jsonc(input).unwrap();
    let value: JsonValue = serde_json::from_str(&clean).unwrap();
    assert_eq!(value["url"], "https://example.test/a/*literal*///b");
    assert_eq!(value["items"], json!([1, 2]));
}

#[cfg(unix)]
#[test]
fn external_import_map_uses_active_root_descriptor_after_root_path_replacement() {
    let parent = tempdir().unwrap();
    let root_path = parent.path().join("root");
    fs::create_dir(&root_path).unwrap();
    fs::write(
        root_path.join("deno.json"),
        r#"{"importMap":"import_map.json"}"#,
    )
    .unwrap();
    fs::write(
        root_path.join("import_map.json"),
        r#"{"imports":{"trusted":"npm:trusted@1"}}"#,
    )
    .unwrap();
    let root = ManifestRoot::open(&root_path).unwrap();

    fs::rename(&root_path, parent.path().join("original")).unwrap();
    fs::create_dir(&root_path).unwrap();
    fs::write(
        root_path.join("deno.json"),
        r#"{"importMap":"import_map.json"}"#,
    )
    .unwrap();
    fs::write(
        root_path.join("import_map.json"),
        r#"{"imports":{"replacement":"npm:replacement@1"}}"#,
    )
    .unwrap();

    let parsed = with_manifest_roots(std::slice::from_ref(&root), || {
        select_manifest(&root).and_then(|manifest| {
            let manifest = manifest.expect("trusted manifest should be selected");
            parse(&root_path, &manifest)
        })
    })
    .unwrap()
    .unwrap();

    assert_eq!(parsed.dependencies.len(), 1);
    assert_eq!(parsed.dependencies[0].name, "trusted");
    assert_eq!(parsed.dependencies[0].requirement, "npm:trusted@1");
}

#[cfg(unix)]
#[test]
fn workspace_enumeration_uses_active_root_after_root_path_replacement() {
    let parent = tempdir().unwrap();
    let root_path = parent.path().join("root");
    fs::create_dir_all(root_path.join("packages/trusted")).unwrap();
    fs::write(
        root_path.join("deno.json"),
        r#"{"workspace":["packages/*"]}"#,
    )
    .unwrap();
    fs::write(
        root_path.join("packages/trusted/deno.json"),
        r#"{"imports":{"trusted":"npm:trusted@1"}}"#,
    )
    .unwrap();
    let root = ManifestRoot::open(&root_path).unwrap();

    fs::rename(&root_path, parent.path().join("original")).unwrap();
    fs::create_dir(&root_path).unwrap();

    let parsed = with_manifest_roots(std::slice::from_ref(&root), || {
        parse(&root_path, &root_path.join("deno.json"))
    })
    .unwrap()
    .unwrap();

    assert!(parsed.dependencies.iter().any(|dependency| {
        dependency.name == "trusted" && dependency.requirement == "npm:trusted@1"
    }));
}

#[test]
fn parses_external_import_maps_and_rejects_invalid_roots() {
    let root = tempdir().unwrap();
    let manifest = root.path().join("deno.json");
    fs::write(&manifest, r#"{"importMap":"maps/import_map.json"}"#).unwrap();
    fs::create_dir(root.path().join("maps")).unwrap();
    fs::write(
        root.path().join("maps/import_map.json"),
        r#"{"imports":{"demo":"npm:demo@1.2.3"}}"#,
    )
    .unwrap();
    let parsed = parse_manifest(root.path());
    assert_eq!(parsed.dependencies.len(), 1);
    assert_eq!(parsed.dependencies[0].requirement, "npm:demo@1.2.3");

    fs::write(&manifest, "[]").unwrap();
    assert!(parse(root.path(), &manifest).is_err());
    fs::write(&manifest, r#"{"importMap":"../outside.json"}"#).unwrap();
    assert!(parse(root.path(), &manifest).is_err());
}

#[test]
fn filters_non_fetchable_import_map_targets() {
    let root = tempdir().unwrap();
    fs::write(
        root.path().join("deno.json"),
        r#"{
            "imports": {
                "local": "./src/mod.ts",
                "file": "file:./vendor/mod.ts",
                "builtin": "node:fs",
                "data": "data:text/javascript,export default 1",
                "npm": "npm:chalk@^5",
                "jsr": "jsr:@std/fs@^1",
                "remote": "https://example.test/mod.ts"
            }
        }"#,
    )
    .unwrap();

    let parsed = parse_manifest(root.path());
    let requirements = parsed
        .dependencies
        .iter()
        .map(|dependency| dependency.requirement.as_str())
        .collect::<std::collections::HashSet<_>>();

    assert_eq!(requirements.len(), 3);
    assert!(requirements.contains("npm:chalk@^5"));
    assert!(requirements.contains("jsr:@std/fs@^1"));
    assert!(requirements.contains("https://example.test/mod.ts"));
}

#[test]
fn normalizes_npm_subpath_specifiers() {
    assert_eq!(
        super::normalize_npm_subpath("npm:lodash@4.17.21/fp"),
        "npm:lodash@4.17.21"
    );
    assert_eq!(
        super::normalize_npm_subpath("npm:@scope/package@1.2.3/subpath"),
        "npm:@scope/package@1.2.3"
    );
    assert_eq!(
        super::normalize_npm_subpath("npm:@scope/package/subpath"),
        "npm:@scope/package"
    );
}

#[test]
fn rejects_external_import_map_combined_with_inline_mappings() {
    let root = tempdir().unwrap();
    let manifest = root.path().join("deno.json");
    fs::write(
        &manifest,
        r#"{"importMap":"import_map.json","imports":{"demo":"npm:demo@1"}}"#,
    )
    .unwrap();
    fs::write(root.path().join("import_map.json"), r#"{"imports":{}}"#).unwrap();

    let error = parse(root.path(), &manifest).unwrap_err();
    assert!(error.to_string().contains("cannot be combined"));
}

#[test]
fn parses_lockfile_selection_forms_and_rejects_escaping_paths() {
    let root = tempdir().unwrap();
    let manifest = root.path().join("deno.json");

    fs::write(&manifest, r#"{"lock":false}"#).unwrap();
    assert_eq!(
        parse_manifest(root.path()).lockfile,
        LockfileSelection::Disabled
    );

    fs::write(&manifest, r#"{"lock":true}"#).unwrap();
    assert_eq!(
        parse_manifest(root.path()).lockfile,
        LockfileSelection::Path("deno.lock".into())
    );

    fs::write(
        &manifest,
        r#"{"lock":{"path":"locks/custom.lock","frozen":true}}"#,
    )
    .unwrap();
    assert_eq!(
        parse_manifest(root.path()).lockfile,
        LockfileSelection::Path("locks/custom.lock".into())
    );

    fs::write(&manifest, r#"{"lock":"../outside.lock"}"#).unwrap();
    assert!(parse(root.path(), &manifest).is_err());
}

#[test]
fn discovers_workspace_members_with_inherited_and_overridden_imports() {
    let root = tempdir().unwrap();
    fs::write(
        root.path().join("deno.json"),
        r#"{
            "workspace":{"members":["packages/*"]},
            "imports":{"shared":"npm:shared@1","root":"jsr:@scope/root@1"}
        }"#,
    )
    .unwrap();
    fs::create_dir_all(root.path().join("packages/a")).unwrap();
    fs::write(
        root.path().join("packages/a/deno.json"),
        r#"{"imports":{"shared":"npm:shared@2","member":"npm:member@3"}}"#,
    )
    .unwrap();
    fs::create_dir_all(root.path().join("packages/b")).unwrap();
    fs::write(
        root.path().join("packages/b/package.json"),
        r#"{"dependencies":{"package-only":"4","local":"workspace:*"}}"#,
    )
    .unwrap();

    let parsed = parse_manifest(root.path());
    let requirements = parsed
        .dependencies
        .iter()
        .map(|dependency| dependency.requirement.as_str())
        .collect::<std::collections::HashSet<_>>();

    assert!(requirements.contains("npm:shared@1"));
    assert!(requirements.contains("npm:shared@2"));
    assert!(requirements.contains("jsr:@scope/root@1"));
    assert!(requirements.contains("npm:member@3"));
    assert!(requirements.contains("npm:package-only@4"));
    assert!(
        !requirements
            .iter()
            .any(|requirement| requirement.contains("workspace:"))
    );
}

#[test]
fn resolves_default_and_named_catalog_dependencies_in_workspace_package_json() {
    let root = tempdir().unwrap();
    fs::write(
        root.path().join("deno.json"),
        r#"{
            "workspace": ["packages/*"],
            "catalog": {"lodash": "4.17.21"},
            "catalogs": {"testing": {"vitest": "3.0.0"}}
        }"#,
    )
    .unwrap();
    fs::create_dir_all(root.path().join("packages/app")).unwrap();
    fs::write(
        root.path().join("packages/app/package.json"),
        r#"{"dependencies":{"lodash":"catalog:"},"optionalDependencies":{"vitest":"catalog:testing"}}"#,
    )
    .unwrap();

    let parsed = parse_manifest(root.path());
    let requirements = parsed
        .dependencies
        .iter()
        .map(|dependency| dependency.requirement.as_str())
        .collect::<std::collections::HashSet<_>>();
    assert!(requirements.contains("npm:lodash@4.17.21"));
    assert!(requirements.contains("npm:vitest@3.0.0"));
}

#[test]
fn rejects_missing_catalog_dependency_in_workspace_package_json() {
    let root = tempdir().unwrap();
    fs::write(
        root.path().join("deno.json"),
        r#"{"workspace":["packages/*"],"catalog":{}}"#,
    )
    .unwrap();
    fs::create_dir_all(root.path().join("packages/app")).unwrap();
    fs::write(
        root.path().join("packages/app/package.json"),
        r#"{"dependencies":{"missing":"catalog:"}}"#,
    )
    .unwrap();

    let error = parse(root.path(), &root.path().join("deno.json")).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("does not define package missing")
    );
}

#[test]
fn workspace_patterns_apply_exclusions_and_require_confined_paths() {
    let root = tempdir().unwrap();
    fs::write(
        root.path().join("deno.json"),
        r#"{"workspace":["packages/*","!packages/ignored"]}"#,
    )
    .unwrap();
    for (member, dependency) in [("included", "included"), ("ignored", "ignored")] {
        fs::create_dir_all(root.path().join("packages").join(member)).unwrap();
        fs::write(
            root.path().join("packages").join(member).join("deno.json"),
            format!(r#"{{"imports":{{"{dependency}":"npm:{dependency}@1"}}}}"#),
        )
        .unwrap();
    }

    let parsed = parse_manifest(root.path());
    assert!(
        parsed
            .dependencies
            .iter()
            .any(|dependency| dependency.name == "included")
    );
    assert!(
        !parsed
            .dependencies
            .iter()
            .any(|dependency| dependency.name == "ignored")
    );

    fs::write(
        root.path().join("deno.json"),
        r#"{"workspace":["../outside/*"]}"#,
    )
    .unwrap();
    assert!(parse(root.path(), &root.path().join("deno.json")).is_err());
}

#[test]
fn bounds_import_mappings_and_aggregate_dependencies() {
    let root = tempdir().unwrap();
    let entries = (0..=super::MAX_IMPORT_MAPPINGS)
        .map(|index| format!(r#""dependency-{index}":"npm:dependency-{index}@1""#))
        .collect::<Vec<_>>()
        .join(",");
    fs::write(
        root.path().join("deno.json"),
        format!(r#"{{"imports":{{{entries}}}}}"#),
    )
    .unwrap();
    let error = parse(root.path(), &root.path().join("deno.json")).unwrap_err();
    assert!(error.to_string().contains("import mappings exceed"));

    let mappings = super::ImportMappings {
        imports: (0..super::MAX_DISCOVERED_DEPENDENCIES)
            .map(|index| (format!("dependency-{index}"), "npm:dependency@1".to_owned()))
            .collect(),
        scoped: Vec::new(),
    };
    let error = super::ensure_dependency_limit(
        root.path(),
        super::mappings_to_dependencies(&mappings).len() + 1,
    )
    .unwrap_err();
    assert!(error.to_string().contains("discovered dependencies exceed"));
}

#[test]
fn bounds_workspace_patterns_before_glob_compilation() {
    let root = tempdir().unwrap();
    let patterns = (0..=super::MAX_WORKSPACE_PATTERNS)
        .map(|index| {
            if index % 2 == 0 {
                format!(r#""packages/{index}""#)
            } else {
                format!(r#""!packages/{index}""#)
            }
        })
        .collect::<Vec<_>>()
        .join(",");
    fs::write(
        root.path().join("deno.json"),
        format!(r#"{{"workspace":[{patterns}]}}"#),
    )
    .unwrap();

    let error = parse(root.path(), &root.path().join("deno.json")).unwrap_err();
    assert!(error.to_string().contains("workspace patterns exceed"));
}

#[test]
fn bounds_workspace_member_expansion() {
    let root = tempdir().unwrap();
    fs::write(
        root.path().join("deno.json"),
        r#"{"workspace":["members/*"]}"#,
    )
    .unwrap();
    for index in 0..=super::MAX_WORKSPACE_MEMBERS {
        let member = root.path().join("members").join(index.to_string());
        fs::create_dir_all(&member).unwrap();
        fs::write(member.join("deno.json"), "{}").unwrap();
    }

    let error = parse(root.path(), &root.path().join("deno.json")).unwrap_err();
    assert!(error.to_string().contains("member limit"));
}

#[cfg(unix)]
#[test]
fn rejects_workspace_member_config_through_symlink() {
    use std::os::unix::fs::symlink;

    let root = tempdir().unwrap();
    let outside = tempdir().unwrap();
    fs::write(
        root.path().join("deno.json"),
        r#"{"workspace":["packages/*"]}"#,
    )
    .unwrap();
    fs::create_dir(root.path().join("packages")).unwrap();
    fs::write(
        outside.path().join("deno.json"),
        r#"{"imports":{"escaped":"npm:escaped@1"}}"#,
    )
    .unwrap();
    symlink(outside.path(), root.path().join("packages/escaped")).unwrap();

    let error = parse(root.path(), &root.path().join("deno.json")).unwrap_err();
    assert!(error.to_string().contains("symbolic link"));
}

#[test]
fn rejects_external_import_map_cycles() {
    let root = tempdir().unwrap();
    let manifest = root.path().join("deno.json");
    fs::write(&manifest, r#"{"importMap":"deno.json"}"#).unwrap();
    let error = parse(root.path(), &manifest).unwrap_err();
    assert!(error.to_string().contains("cycle detected"));

    fs::write(&manifest, r#"{"importMap":"a.json"}"#).unwrap();
    fs::write(root.path().join("a.json"), r#"{"importMap":"b.json"}"#).unwrap();
    fs::write(root.path().join("b.json"), r#"{"importMap":"a.json"}"#).unwrap();
    let error = parse(root.path(), &manifest).unwrap_err();
    assert!(error.to_string().contains("cycle detected"));
}

#[test]
fn bounds_external_import_map_recursion() {
    let root = tempdir().unwrap();
    let manifest = root.path().join("deno.json");
    fs::write(&manifest, r#"{"importMap":"map-0.json"}"#).unwrap();
    for index in 0..32 {
        fs::write(
            root.path().join(format!("map-{index}.json")),
            format!(r#"{{"importMap":"map-{}.json"}}"#, index + 1),
        )
        .unwrap();
    }
    fs::write(root.path().join("map-32.json"), r#"{"imports":{}}"#).unwrap();

    let error = parse(root.path(), &manifest).unwrap_err();
    assert!(error.to_string().contains("recursion exceeds"));
}

#[cfg(unix)]
#[test]
fn rejects_external_import_map_through_intermediate_symlink() {
    use std::os::unix::fs::symlink;

    let root = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let manifest = root.path().join("deno.json");
    fs::write(&manifest, r#"{"importMap":"maps/import_map.json"}"#).unwrap();
    fs::write(
        outside.path().join("import_map.json"),
        r#"{"imports":{"escaped":"npm:escaped@1"}}"#,
    )
    .unwrap();
    symlink(outside.path(), root.path().join("maps")).unwrap();

    assert!(parse(root.path(), &manifest).is_err());
}

#[test]
fn jsonc_rejects_unterminated_constructs() {
    assert_eq!(
        strip_jsonc("{/* never closed").unwrap_err(),
        "unterminated block comment"
    );
    assert_eq!(
        strip_jsonc(r#"{"value":"never closed}"#).unwrap_err(),
        "unterminated string"
    );
}

#[test]
fn lockfile_version_requires_an_object_and_string_version() {
    let path = Path::new("deno.lock");
    assert!(validate_lockfile_version(path, &json!([])).is_err());
    assert!(validate_lockfile_version(path, &json!({"version": 4})).is_err());
    assert!(validate_lockfile_version(path, &json!({"remote": {}})).is_err());
    assert!(validate_lockfile_version(path, &json!({})).is_err());
    assert!(validate_lockfile_version(path, &json!({"version": "6"})).is_err());
}

#[test]
fn versionless_legacy_lockfiles_are_limited_to_url_integrity_maps() {
    let path = Path::new("deno.lock");
    let lockfile = json!({"https://example.test/mod.ts": "sha256-legacy"});
    assert_eq!(
        validate_lockfile_version(path, &lockfile).unwrap(),
        LockVersion::Legacy
    );

    let mut remote = dependency("https://example.test/mod.ts");
    assert!(enrich_dependency(
        &lockfile,
        LockVersion::Legacy,
        &mut remote
    ));
    assert_eq!(
        remote.resolved_version.as_deref(),
        Some(remote.requirement.as_str())
    );
    assert_eq!(remote.integrity.as_deref(), Some("sha256-legacy"));
}

#[test]
fn matches_remote_lockfile_urls_after_canonicalization() {
    let lockfile = json!({
        "version": "4",
        "remote": {"https://example.test/mod.ts": "sha256-canonical"}
    });
    let mut remote = dependency("https://example.test:443/mod.ts");

    assert!(enrich_dependency(&lockfile, LockVersion::V4, &mut remote));
    assert_eq!(remote.integrity.as_deref(), Some("sha256-canonical"));
    assert_eq!(
        remote.resolved_version.as_deref(),
        Some("https://example.test:443/mod.ts")
    );
}

#[test]
fn resolves_v2_nested_npm_layout() {
    let lockfile = json!({
        "version": "2",
        "npm": {
            "specifiers": {"left-pad@^1": "left-pad@1.3.0"},
            "packages": {"left-pad@1.3.0": {"integrity": "sha512-v2"}}
        }
    });
    let mut npm = dependency("npm:left-pad@^1");
    assert!(enrich_dependency(&lockfile, LockVersion::V2, &mut npm));
    assert_eq!(npm.resolved_version.as_deref(), Some("1.3.0"));
    assert_eq!(npm.integrity.as_deref(), Some("sha512-v2"));
}

#[test]
fn resolves_v3_packages_specifiers_and_npm_layout() {
    let lockfile = json!({
        "version": "3",
        "packages": {
            "specifiers": {"npm:@scope/pkg@^2": "npm:@scope/pkg@2.1.0"},
            "npm": {"@scope/pkg@2.1.0": {"integrity": "sha512-v3"}}
        }
    });
    let mut npm = dependency("npm:@scope/pkg@^2");
    assert!(enrich_dependency(&lockfile, LockVersion::V3, &mut npm));
    assert_eq!(npm.resolved_version.as_deref(), Some("2.1.0"));
    assert_eq!(npm.integrity.as_deref(), Some("sha512-v3"));
}

#[test]
fn rejects_out_of_range_npm_and_jsr_specifiers() {
    let lockfile = json!({
        "version": "4",
        "specifiers": {
            "npm:example@^1.0.0": "example@9.0.0",
            "jsr:@scope/example@^1.0.0": "@scope/example@9.0.0"
        },
        "npm": {"example@9.0.0": {"integrity": "sha512-example"}},
        "jsr": {"@scope/example@9.0.0": {"integrity": "a".repeat(64)}}
    });

    let mut npm = dependency("npm:example@^1.0.0");
    assert!(!enrich_dependency(&lockfile, LockVersion::V4, &mut npm));
    assert!(npm.resolved_version.is_none());

    let mut jsr = dependency("jsr:@scope/example@^1.0.0");
    assert!(!enrich_dependency(&lockfile, LockVersion::V4, &mut jsr));
    assert!(jsr.resolved_version.is_none());
}

#[test]
fn preserves_v4_and_v5_registry_and_remote_layouts() {
    let digest = "a".repeat(64);
    for version in [LockVersion::V4, LockVersion::V5] {
        let lockfile = json!({
            "specifiers": {
                "npm:chalk@^5": "5.3.0",
                "jsr:@std/fs": "1.0.0"
            },
            "npm": {"chalk@5.3.0": {"integrity": "sha512-npm"}},
            "jsr": {"@std/fs@1.0.0": {"integrity": digest}},
            "remote": {"https://example.test/mod.ts": "sha256-remote"}
        });

        let mut npm = dependency("npm:chalk@^5");
        assert!(enrich_dependency(&lockfile, version, &mut npm));
        assert_eq!(npm.resolved_version.as_deref(), Some("5.3.0"));
        assert_eq!(npm.integrity.as_deref(), Some("sha512-npm"));

        let mut jsr = dependency("jsr:@std/fs");
        assert!(enrich_dependency(&lockfile, version, &mut jsr));
        assert_eq!(jsr.resolved_version.as_deref(), Some("1.0.0"));
        assert_eq!(
            jsr.integrity.as_deref(),
            Some(format!("sha256:{digest}").as_str())
        );
        assert_eq!(
            jsr.source_url.as_deref(),
            Some("https://jsr.io/@std/fs/1.0.0_meta.json")
        );

        let mut remote = dependency("https://example.test/mod.ts");
        assert!(enrich_dependency(&lockfile, version, &mut remote));
        assert_eq!(
            remote.resolved_version.as_deref(),
            Some(remote.requirement.as_str())
        );
        assert_eq!(remote.integrity.as_deref(), Some("sha256-remote"));
    }
}

#[test]
fn custom_and_disabled_lockfile_selections_are_respected() {
    let root = tempdir().unwrap();
    fs::create_dir(root.path().join("locks")).unwrap();
    fs::write(
        root.path().join("locks/custom.lock"),
        r#"{"version":"4","specifiers":{"npm:demo@^1":"1.2.3"},"npm":{"demo@1.2.3":{"integrity":"sha512-custom"}}}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("deno.lock"),
        r#"{"version":"4","specifiers":{"npm:demo@^1":"9.9.9"},"npm":{"demo@9.9.9":{"integrity":"sha512-stale"}}}"#,
    )
    .unwrap();

    let mut custom = vec![dependency("npm:demo@^1")];
    let mut lockfiles = Vec::new();
    enrich(
        root.path(),
        &LockfileSelection::Path("locks/custom.lock".into()),
        &mut custom,
        &mut lockfiles,
    )
    .unwrap();
    assert_eq!(custom[0].resolved_version.as_deref(), Some("1.2.3"));
    assert_eq!(custom[0].integrity.as_deref(), Some("sha512-custom"));
    assert_eq!(lockfiles, vec![root.path().join("locks/custom.lock")]);

    let mut disabled = vec![dependency("npm:demo@^1")];
    let mut lockfiles = Vec::new();
    enrich(
        root.path(),
        &LockfileSelection::Disabled,
        &mut disabled,
        &mut lockfiles,
    )
    .unwrap();
    assert!(disabled[0].resolved_version.is_none());
    assert!(lockfiles.is_empty());
}

#[cfg(unix)]
#[test]
fn rejects_custom_lockfile_through_intermediate_symlink() {
    use std::os::unix::fs::symlink;

    let root = tempdir().unwrap();
    let outside = tempdir().unwrap();
    fs::write(outside.path().join("custom.lock"), r#"{"version":"4"}"#).unwrap();
    symlink(outside.path(), root.path().join("locks")).unwrap();
    let mut dependencies = Vec::new();
    let mut lockfiles = Vec::new();

    assert!(
        enrich(
            root.path(),
            &LockfileSelection::Path("locks/custom.lock".into()),
            &mut dependencies,
            &mut lockfiles,
        )
        .is_err()
    );
}

#[test]
fn enrich_does_not_mark_dependencies_without_matching_lock_evidence() {
    let root = tempdir().unwrap();
    fs::write(
        root.path().join("deno.lock"),
        r#"{"version":"4","specifiers":{},"npm":{},"remote":{}}"#,
    )
    .unwrap();
    let mut dependencies = vec![
        dependency("npm:missing@^1"),
        dependency("https://example.test/missing.ts"),
    ];
    let mut lockfiles = Vec::new();

    enrich(
        root.path(),
        &LockfileSelection::default(),
        &mut dependencies,
        &mut lockfiles,
    )
    .unwrap();

    assert_eq!(lockfiles, vec![root.path().join("deno.lock")]);
    for dependency in dependencies {
        assert!(dependency.resolved_version.is_none());
        assert!(dependency.integrity.is_none());
        assert!(dependency.lockfile.is_none());
    }
}
