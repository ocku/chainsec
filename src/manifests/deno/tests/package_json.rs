use super::*;

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
fn preserves_non_registry_workspace_package_json_dependencies() {
    let root = tempdir().unwrap();
    let revision = "0123456789012345678901234567890123456789";
    fs::write(
        root.path().join("deno.json"),
        r#"{"workspace":["packages/*"]}"#,
    )
    .unwrap();
    fs::create_dir_all(root.path().join("packages/app")).unwrap();
    fs::write(
        root.path().join("packages/app/package.json"),
        format!(
            r#"{{"dependencies":{{"github":"github:owner/repository#{revision}","git":"git+ssh://git@example.test/owner/repository.git#main","tarball":"https://example.test/tool.tgz","jsr":"jsr:@std/assert@^1"}}}}"#
        ),
    )
    .unwrap();

    let dependencies = parse_manifest(root.path()).dependencies;
    let github = dependencies
        .iter()
        .find(|dependency| dependency.name == "github")
        .unwrap();
    assert_eq!(
        github.requirement,
        format!("github:owner/repository#{revision}")
    );
    assert_eq!(github.resolved_version.as_deref(), Some(revision));
    assert_eq!(
        github.source_url.as_deref(),
        Some(format!("https://codeload.github.com/owner/repository/tar.gz/{revision}").as_str())
    );

    let git = dependencies
        .iter()
        .find(|dependency| dependency.name == "git")
        .unwrap();
    assert_eq!(
        git.requirement,
        "git+ssh://git@example.test/owner/repository.git#main"
    );

    let tarball = dependencies
        .iter()
        .find(|dependency| dependency.name == "tarball")
        .unwrap();
    assert_eq!(tarball.requirement, "https://example.test/tool.tgz");
    assert_eq!(
        tarball.source_url.as_deref(),
        Some("https://example.test/tool.tgz")
    );

    let jsr = dependencies
        .iter()
        .find(|dependency| dependency.name == "jsr")
        .unwrap();
    assert_eq!(jsr.requirement, "jsr:@std/assert@^1");
}

#[test]
fn preserves_case_insensitive_package_url_and_git_protocols() {
    let root = tempdir().unwrap();
    fs::write(
        root.path().join("deno.json"),
        r#"{"workspace":["packages/*"]}"#,
    )
    .unwrap();
    fs::create_dir_all(root.path().join("packages/app")).unwrap();
    fs::write(
        root.path().join("packages/app/package.json"),
        r#"{"dependencies":{"tarball":"HTTPS://example.test/tool.tgz","git":"GIT+SSH://git@example.test/owner/repository.git#main"}}"#,
    )
    .unwrap();

    let dependencies = parse_manifest(root.path()).dependencies;
    let tarball = dependencies
        .iter()
        .find(|dependency| dependency.name == "tarball")
        .unwrap();
    assert_eq!(tarball.requirement, "HTTPS://example.test/tool.tgz");
    assert_eq!(
        tarball.source_url.as_deref(),
        Some("HTTPS://example.test/tool.tgz")
    );

    let git = dependencies
        .iter()
        .find(|dependency| dependency.name == "git")
        .unwrap();
    assert_eq!(
        git.requirement,
        "GIT+SSH://git@example.test/owner/repository.git#main"
    );
}

#[test]
fn root_package_json_catalogs_override_deno_catalogs() {
    let root = tempdir().unwrap();
    fs::write(
        root.path().join("deno.json"),
        r#"{"workspace":["packages/*"],"catalog":{"react":"^18"}}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"catalog":{"react":"^19"},"catalogs":{"testing":{"vitest":"^3"}}}"#,
    )
    .unwrap();
    fs::create_dir_all(root.path().join("packages/app")).unwrap();
    fs::write(
        root.path().join("packages/app/package.json"),
        r#"{"dependencies":{"react":"catalog:"},"devDependencies":{"vitest":"catalog:testing"}}"#,
    )
    .unwrap();

    let requirements = parse_manifest(root.path())
        .dependencies
        .into_iter()
        .map(|dependency| dependency.requirement)
        .collect::<std::collections::HashSet<_>>();
    assert!(requirements.contains("npm:react@^19"));
    assert!(requirements.contains("npm:vitest@^3"));
    assert!(!requirements.contains("npm:react@^18"));
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
fn preserves_non_member_local_workspace_package_json_dependencies() {
    let root = tempdir().unwrap();
    fs::write(
        root.path().join("deno.json"),
        r#"{"workspace":["packages/*"]}"#,
    )
    .unwrap();
    fs::create_dir_all(root.path().join("packages/app")).unwrap();
    let absolute = root.path().join("absolute-local");
    let package = serde_json::json!({
        "dependencies": {
            "file-local": "file:../file-local",
            "link-local": "link:../link-local",
            "portal-local": "portal:../portal-local",
            "relative-local": "./relative-local",
            "parent-local": "../parent-local",
            "absolute-local": absolute.to_str().unwrap(),
            "workspace-member": "workspace:*"
        }
    });
    fs::write(
        root.path().join("packages/app/package.json"),
        serde_json::to_vec(&package).unwrap(),
    )
    .unwrap();

    let requirements = parse_manifest(root.path())
        .dependencies
        .into_iter()
        .map(|dependency| (dependency.name, dependency.requirement))
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(requirements["file-local"], "file:../file-local");
    assert_eq!(requirements["link-local"], "link:../link-local");
    assert_eq!(requirements["portal-local"], "portal:../portal-local");
    assert_eq!(requirements["relative-local"], "./relative-local");
    assert_eq!(requirements["parent-local"], "../parent-local");
    assert_eq!(requirements["absolute-local"], absolute.to_str().unwrap());
    assert!(!requirements.contains_key("workspace-member"));
}
