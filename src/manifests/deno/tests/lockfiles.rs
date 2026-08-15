use super::*;

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
fn resolves_exact_npm_dist_tag_mappings() {
    for tag in ["latest", "next"] {
        let selector = format!("npm:example@{tag}");
        let mut lockfile = json!({
            "version": "4",
            "specifiers": {},
            "npm": {"example@1.2.3": {"integrity": "sha512-example"}}
        });
        lockfile["specifiers"][&selector] = json!("example@1.2.3");
        let mut npm = dependency(&selector);

        assert!(enrich_dependency(&lockfile, LockVersion::V4, &mut npm));
        assert_eq!(npm.resolved_version.as_deref(), Some("1.2.3"));
        assert_eq!(npm.integrity.as_deref(), Some("sha512-example"));
    }
}

#[test]
fn dist_tags_require_exact_mappings_and_semver_locked_targets() {
    let inferred = json!({
        "version": "4",
        "specifiers": {"npm:example@latest/subpath": "example@1.2.3"},
        "npm": {"example@1.2.3": {"integrity": "sha512-example"}}
    });
    let mut npm = dependency("npm:example@latest");
    assert!(!enrich_dependency(&inferred, LockVersion::V4, &mut npm));

    let malformed = json!({
        "version": "4",
        "specifiers": {"npm:example@latest": "example@not-semver"},
        "npm": {"example@not-semver": {"integrity": "sha512-example"}}
    });
    let mut npm = dependency("npm:example@latest");
    assert!(!enrich_dependency(&malformed, LockVersion::V4, &mut npm));
}

#[test]
fn does_not_resolve_ambiguous_registry_subpath_specifiers() {
    let lockfile = json!({
        "version": "4",
        "specifiers": {
            "npm:example@^1/first": "example@1.1.0",
            "npm:example@^1/second": "example@1.2.0"
        },
        "npm": {
            "example@1.1.0": {"integrity": "sha512-first"},
            "example@1.2.0": {"integrity": "sha512-second"}
        }
    });
    let mut npm = dependency("npm:example@^1");

    assert!(!enrich_dependency(&lockfile, LockVersion::V4, &mut npm));
    assert!(npm.resolved_version.is_none());
    assert!(npm.integrity.is_none());
}

#[test]
fn resolves_jsr_subpath_specifiers() {
    let digest = "a".repeat(64);
    let lockfile = json!({
        "version": "4",
        "specifiers": {
            "jsr:@std/path@^1.0.0/posix": "@std/path@1.0.8"
        },
        "jsr": {"@std/path@1.0.8": {"integrity": digest}}
    });
    let mut jsr = dependency("jsr:@std/path@^1.0.0/posix");

    assert!(enrich_dependency(&lockfile, LockVersion::V4, &mut jsr));
    assert_eq!(jsr.resolved_version.as_deref(), Some("1.0.8"));
    assert_eq!(
        jsr.integrity.as_deref(),
        Some(format!("sha256:{digest}").as_str())
    );
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
fn resolves_v5_redirected_remote_dependencies() {
    let root = tempdir().unwrap();
    fs::write(
        root.path().join("deno.lock"),
        r#"{"version":"5","redirects":{"https://origin.example/mod.ts":"https://cdn.example/mod.ts"},"remote":{"https://cdn.example/mod.ts":"sha256-redirected"}}"#,
    )
    .unwrap();
    let mut dependencies = vec![dependency("https://origin.example/mod.ts")];

    enrich(
        root.path(),
        &LockfileSelection::default(),
        &mut dependencies,
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(
        dependencies[0].integrity.as_deref(),
        Some("sha256-redirected")
    );
    assert!(dependencies[0].deno_lockfile_snapshot.is_some());
}

#[test]
fn rejects_remote_redirect_chains_beyond_the_hop_limit() {
    let redirects = (0..2)
        .map(|index| {
            (
                format!("https://example.test/{index}"),
                JsonValue::String(format!("https://example.test/{}", index + 1)),
            )
        })
        .collect::<serde_json::Map<String, JsonValue>>();
    let lockfile = json!({
        "version": "5",
        "redirects": redirects,
        "remote": {"https://example.test/2": "sha256-remote"}
    });
    let mut remote = dependency("https://example.test/0");

    assert!(!enrich_dependency_with_redirect_limit(
        &lockfile,
        LockVersion::V5,
        &mut remote,
        1,
    ));
    assert!(remote.integrity.is_none());

    assert!(enrich_dependency_with_redirect_limit(
        &lockfile,
        LockVersion::V5,
        &mut remote,
        2,
    ));
    assert_eq!(remote.integrity.as_deref(), Some("sha256-remote"));
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
fn remote_dependencies_share_their_lockfile_snapshot() {
    let root = tempdir().unwrap();
    fs::write(
        root.path().join("deno.lock"),
        r#"{"version":"4","remote":{"https://example.test/a.ts":"sha256-a","https://example.test/b.ts":"sha256-b"}}"#,
    )
    .unwrap();
    let mut dependencies = vec![
        dependency("https://example.test/a.ts"),
        dependency("https://example.test/b.ts"),
    ];

    enrich(
        root.path(),
        &LockfileSelection::default(),
        &mut dependencies,
        &mut Vec::new(),
    )
    .unwrap();

    assert!(
        dependencies[0]
            .deno_lockfile_snapshot
            .as_ref()
            .unwrap()
            .shares_remote_integrities_with(
                dependencies[1].deno_lockfile_snapshot.as_ref().unwrap()
            )
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
