use super::*;

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
fn recognizes_mixed_case_remote_import_map_urls() {
    let root = tempdir().unwrap();
    fs::write(
        root.path().join("deno.json"),
        r#"{"imports":{"remote":"HTTPS://example.test/mod.ts"}}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("deno.lock"),
        r#"{"version":"4","remote":{"https://example.test/mod.ts":"sha256-remote"}}"#,
    )
    .unwrap();

    let mut parsed = parse_manifest(root.path());
    assert_eq!(
        parsed.dependencies[0].requirement,
        "HTTPS://example.test/mod.ts"
    );
    enrich(
        root.path(),
        &LockfileSelection::default(),
        &mut parsed.dependencies,
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(
        parsed.dependencies[0].integrity.as_deref(),
        Some("sha256-remote")
    );
    assert!(parsed.dependencies[0].deno_lockfile_snapshot.is_some());
}

#[test]
fn normalizes_npm_subpath_specifiers() {
    assert_eq!(
        super::import_map::normalize_npm_subpath("npm:lodash@4.17.21/fp"),
        "npm:lodash@4.17.21"
    );
    assert_eq!(
        super::import_map::normalize_npm_subpath("npm:@scope/package@1.2.3/subpath"),
        "npm:@scope/package@1.2.3"
    );
    assert_eq!(
        super::import_map::normalize_npm_subpath("npm:@scope/package/subpath"),
        "npm:@scope/package"
    );
    assert_eq!(
        super::import_map::normalize_jsr_subpath("jsr:@scope/package@1.2.3/subpath"),
        "jsr:@scope/package@1.2.3"
    );
    assert_eq!(
        super::import_map::normalize_jsr_subpath("jsr:/@scope/package@1.2.3/subpath"),
        "jsr:@scope/package@1.2.3"
    );
}

#[test]
fn normalizes_url_style_registry_import_map_specifiers() {
    let root = tempdir().unwrap();
    fs::write(
        root.path().join("deno.json"),
        r#"{"imports":{"path":"jsr:/@std/path@^1.0.0/posix"}}"#,
    )
    .unwrap();
    let digest = "a".repeat(64);
    fs::write(
        root.path().join("deno.lock"),
        format!(
            r#"{{"version":"5","specifiers":{{"jsr:/@std/path@^1.0.0/posix":"@std/path@1.0.8"}},"jsr":{{"@std/path@1.0.8":{{"integrity":"{digest}"}}}}}}"#
        ),
    )
    .unwrap();

    let parsed = parse_manifest(root.path());
    assert_eq!(parsed.dependencies[0].requirement, "jsr:@std/path@^1.0.0");
    let mut dependencies = parsed.dependencies;
    enrich(
        root.path(),
        &LockfileSelection::default(),
        &mut dependencies,
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(dependencies[0].resolved_version.as_deref(), Some("1.0.8"));
    assert_eq!(
        dependencies[0].integrity.as_deref(),
        Some(format!("sha256:{digest}").as_str())
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
fn external_import_maps_respect_the_global_depth_limit() {
    let root = tempdir().unwrap();
    let manifest = root.path().join("deno.json");
    fs::write(&manifest, r#"{"importMap":"a.json"}"#).unwrap();
    fs::write(root.path().join("a.json"), r#"{"importMap":"b.json"}"#).unwrap();
    fs::write(
        root.path().join("b.json"),
        r#"{"imports":{"demo":"npm:demo@1"}}"#,
    )
    .unwrap();

    let parsed = super::parse_with_limits(
        root.path(),
        &manifest,
        &EngineLimits {
            max_package_depth: 2,
            ..EngineLimits::default()
        },
    )
    .unwrap();
    assert_eq!(parsed.dependencies.len(), 1);

    let error = super::parse_with_limits(
        root.path(),
        &manifest,
        &EngineLimits {
            max_package_depth: 1,
            ..EngineLimits::default()
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("depth limit"));
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
