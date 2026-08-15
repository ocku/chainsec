use super::*;

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
        r#"{"dependencies":{"package-only":"4","local":"workspace:*"},"devDependencies":{"development-only":"5"}}"#,
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
    assert!(requirements.contains("npm:development-only@5"));
    assert!(
        !requirements
            .iter()
            .any(|requirement| requirement.contains("workspace:"))
    );
}

#[test]
fn resolves_catalog_imports_in_workspace_member_config() {
    let root = tempdir().unwrap();
    fs::write(
        root.path().join("deno.json"),
        r#"{"workspace":["packages/*"],"catalog":{"chalk":"^5"},"catalogs":{"testing":{"vitest":"^3"}}}"#,
    )
    .unwrap();
    fs::create_dir_all(root.path().join("packages/app")).unwrap();
    fs::write(
        root.path().join("packages/app/deno.json"),
        r#"{"imports":{"chalk":"catalog:","vitest":"catalog:testing"}}"#,
    )
    .unwrap();

    let requirements = parse_manifest(root.path())
        .dependencies
        .into_iter()
        .map(|dependency| dependency.requirement)
        .collect::<std::collections::HashSet<_>>();
    assert!(requirements.contains("npm:chalk@^5"));
    assert!(requirements.contains("npm:vitest@^3"));
}

#[test]
fn workspace_patterns_apply_exclusions_and_require_confined_paths() {
    let root = tempdir().unwrap();
    fs::write(
        root.path().join("deno.json"),
        r#"{"workspace":["packages/*","!packages/ignored"]}"#,
    )
    .unwrap();
    for (member, dependency) in [
        ("included", "included"),
        ("ignored", "ignored"),
        ("included/nested", "nested"),
    ] {
        fs::create_dir_all(root.path().join("packages").join(member)).unwrap();
        fs::write(
            root.path().join("packages").join(member).join("deno.json"),
            format!(r#"{{"imports":{{"{dependency}":"npm:{dependency}@1"}}}}"#),
        )
        .unwrap();
    }

    let parsed = super::parse_with_limits(
        root.path(),
        &root.path().join("deno.json"),
        &EngineLimits {
            max_package_depth: 4,
            ..EngineLimits::default()
        },
    )
    .unwrap();
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
            .any(|dependency| dependency.name == "ignored" || dependency.name == "nested")
    );

    fs::write(
        root.path().join("deno.json"),
        r#"{"workspace":["../outside/*"]}"#,
    )
    .unwrap();
    assert!(parse(root.path(), &root.path().join("deno.json")).is_err());
}

#[test]
fn dependency_expansion_respects_the_configured_package_limit() {
    let root = tempdir().unwrap();
    let manifest = root.path().join("deno.json");
    fs::write(
        &manifest,
        r#"{"workspace":["packages/*"],"imports":{"root":"npm:root@1"}}"#,
    )
    .unwrap();
    fs::create_dir_all(root.path().join("packages/app")).unwrap();
    fs::write(
        root.path().join("packages/app/deno.json"),
        r#"{"imports":{"member":"npm:member@1"}}"#,
    )
    .unwrap();

    let error = super::parse_with_limits(
        root.path(),
        &manifest,
        &EngineLimits {
            max_packages: 1,
            ..EngineLimits::default()
        },
    )
    .unwrap_err();

    assert!(matches!(error, crate::error::Error::LimitExceeded { .. }));
    assert!(error.to_string().contains("manifest dependencies"));
}

#[test]
fn workspace_traversal_only_fails_for_matching_depth_boundaries() {
    let root = tempdir().unwrap();
    let manifest = root.path().join("deno.json");
    fs::write(&manifest, r#"{"workspace":["packages/*"]}"#).unwrap();
    fs::create_dir_all(root.path().join("packages/app")).unwrap();
    fs::write(root.path().join("packages/app/deno.json"), "{}").unwrap();
    let limits = EngineLimits {
        max_package_depth: 1,
        ..EngineLimits::default()
    };

    let depth_error = super::parse_with_limits(root.path(), &manifest, &limits).unwrap_err();
    assert!(matches!(
        depth_error,
        crate::error::Error::LimitExceeded { ref resource, .. } if resource == "workspace depth"
    ));

    fs::write(&manifest, r#"{"workspace":["examples/*"]}"#).unwrap();
    let parsed = super::parse_with_limits(root.path(), &manifest, &limits).unwrap();
    assert!(parsed.dependencies.is_empty());

    fs::write(&manifest, r#"{"workspace":["packages"]}"#).unwrap();
    let depth_error = super::parse_with_limits(root.path(), &manifest, &limits).unwrap_err();
    assert!(matches!(
        depth_error,
        crate::error::Error::LimitExceeded { ref resource, .. } if resource == "workspace depth"
    ));
}

#[test]
fn workspace_traversal_respects_the_configured_entry_limit() {
    let root = tempdir().unwrap();
    let manifest = root.path().join("deno.json");
    fs::write(&manifest, r#"{"workspace":["packages/*"]}"#).unwrap();
    fs::create_dir_all(root.path().join("packages/app")).unwrap();
    fs::write(root.path().join("packages/app/deno.json"), "{}").unwrap();

    let error = super::parse_with_limits(
        root.path(),
        &manifest,
        &EngineLimits {
            max_package_depth: 3,
            max_source_files: 1,
            ..EngineLimits::default()
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("workspace entries"));
}

#[test]
fn rejects_catalogs_in_workspace_members() {
    let root = tempdir().unwrap();
    fs::write(
        root.path().join("deno.json"),
        r#"{"workspace":["packages/*"]}"#,
    )
    .unwrap();
    fs::create_dir_all(root.path().join("packages/app")).unwrap();
    fs::write(
        root.path().join("packages/app/deno.json"),
        r#"{"catalog":{"example":"1.0.0"}}"#,
    )
    .unwrap();

    let error = parse(root.path(), &root.path().join("deno.json")).unwrap_err();
    assert!(error.to_string().contains("may not configure catalogs"));
}

#[test]
fn does_not_count_inherited_root_mappings_for_each_workspace_member() {
    let root = tempdir().unwrap();
    let imports = (0..65)
        .map(|index| format!(r#""dependency-{index}":"npm:dependency-{index}@1""#))
        .collect::<Vec<_>>()
        .join(",");
    fs::write(
        root.path().join("deno.json"),
        format!(r#"{{"workspace":["packages/*"],"imports":{{{imports}}}}}"#),
    )
    .unwrap();
    for index in 0..2 {
        let member = root.path().join("packages").join(index.to_string());
        fs::create_dir_all(&member).unwrap();
        fs::write(member.join("deno.json"), "{}").unwrap();
    }

    let parsed = parse_manifest(root.path());
    assert_eq!(parsed.dependencies.len(), 65);
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
