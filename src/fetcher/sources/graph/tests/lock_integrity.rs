use super::*;

#[test]
fn lockfile_urls_use_the_graph_module_canonical_form() {
    let child = Url::parse("https://example.test/child.ts").unwrap();
    let child_bytes = b"export const safe = true;\n";
    let contents = format!(
        r#"{{"version":"4","remote":{{"https://example.test:443/child.ts":"{}"}}}}"#,
        integrity(child_bytes)
    );
    let snapshot = lockfile_snapshot(&contents);

    verify_graph_module_integrity(
        child_bytes,
        &child,
        &child,
        false,
        &Url::parse("https://example.test/root.ts").unwrap(),
        Some(&integrity(b"root")),
        Some(snapshot.remote_integrities()),
    )
    .unwrap();
}

#[test]
fn versionless_legacy_lockfile_root_entries_are_remote_integrities() {
    let snapshot = lockfile_snapshot(
        r#"{
            "https://example.test:443/root.ts": "sha256-root",
            "http://example.test:80/child.ts": "sha256-child"
        }"#,
    );

    assert_eq!(
        snapshot.remote_integrities(),
        &HashMap::from([
            (
                "https://example.test/root.ts".to_owned(),
                "sha256-root".to_owned(),
            ),
            (
                "http://example.test/child.ts".to_owned(),
                "sha256-child".to_owned(),
            ),
        ])
    );
}

#[test]
fn malformed_versionless_roots_are_not_partially_loaded_as_legacy_integrities() {
    for contents in [
        r#"{}"#,
        r#"{"https://example.test/root.ts":"sha256-root","metadata":"value"}"#,
        r#"{"https://example.test/root.ts":"sha256-root","https://example.test/child.ts":{}}"#,
        r#"{"version":null,"https://example.test/root.ts":"sha256-root"}"#,
        r#"["https://example.test/root.ts","sha256-root"]"#,
    ] {
        let snapshot = lockfile_snapshot(contents);

        assert!(
            snapshot.remote_integrities().is_empty(),
            "unexpected integrities for {contents}"
        );
    }
}

#[test]
fn modern_remote_object_remains_authoritative() {
    let snapshot = lockfile_snapshot(
        r#"{
            "https://example.test/root.ts": "sha256-legacy",
            "remote": {"https://example.test/child.ts": "sha256-modern"}
        }"#,
    );

    assert_eq!(
        snapshot.remote_integrities(),
        &HashMap::from([(
            "https://example.test/child.ts".to_owned(),
            "sha256-modern".to_owned(),
        )])
    );
}

#[test]
fn root_only_graph_accepts_declared_integrity_without_a_lockfile() {
    let root = Url::parse("https://example.test/root.ts").unwrap();
    let bytes = b"export const safe = true;\n";

    verify_graph_module_integrity(
        bytes,
        &root,
        &root,
        true,
        &root,
        Some(&integrity(bytes)),
        None,
    )
    .unwrap();
}

#[test]
fn graph_root_integrity_is_checked_even_with_a_lockfile() {
    let root = Url::parse("https://example.test/root.ts").unwrap();
    let mut locked = HashMap::new();
    locked.insert(root.to_string(), integrity(b"root"));

    let error = verify_graph_module_integrity(
        b"changed",
        &root,
        &root,
        true,
        &root,
        Some(&integrity(b"root")),
        Some(&locked),
    )
    .unwrap_err();
    assert!(error.to_string().contains("integrity verification failed"));
}

#[test]
fn graph_children_require_a_lockfile_integrity_binding() {
    let root = Url::parse("https://example.test/root.ts").unwrap();
    let child = Url::parse("https://example.test/child.ts").unwrap();

    let error = verify_graph_module_integrity(
        b"child",
        &child,
        &child,
        false,
        &root,
        Some(&integrity(b"root")),
        None,
    )
    .unwrap_err();

    assert!(error.to_string().contains("no lockfile integrity binding"));
}

#[test]
fn graph_modules_require_lockfile_integrity_when_lockfile_is_present() {
    let root = Url::parse("https://example.test/root.ts").unwrap();
    let child = Url::parse("https://example.test/child.ts").unwrap();
    let mut locked = HashMap::new();
    locked.insert(root.to_string(), integrity(b"root"));

    let error = verify_graph_module_integrity(
        b"child",
        &child,
        &child,
        false,
        &root,
        Some(&integrity(b"root")),
        Some(&locked),
    )
    .unwrap_err();
    assert!(error.to_string().contains("has no expected integrity"));
}

#[test]
fn graph_children_verify_against_their_lockfile_integrity() {
    let root = Url::parse("https://example.test/root.ts").unwrap();
    let child = Url::parse("https://example.test/child.ts").unwrap();
    let child_bytes = b"export const safe = true;\n";
    let mut locked = HashMap::new();
    locked.insert(root.to_string(), integrity(b"root"));
    locked.insert(child.to_string(), integrity(child_bytes));

    verify_graph_module_integrity(
        child_bytes,
        &child,
        &child,
        false,
        &root,
        Some(&integrity(b"root")),
        Some(&locked),
    )
    .unwrap();

    let error = verify_graph_module_integrity(
        b"export const changed = true;\n",
        &child,
        &child,
        false,
        &root,
        Some(&integrity(b"root")),
        Some(&locked),
    )
    .unwrap_err();
    assert!(error.to_string().contains("integrity verification failed"));
}

#[test]
fn redirected_graph_accepts_requested_only_lockfile_binding() {
    let root = Url::parse("https://example.test/root.ts").unwrap();
    let requested = Url::parse("https://example.test/child.ts").unwrap();
    let effective = Url::parse("https://example.test/v1/child.ts").unwrap();
    let bytes = b"export const safe = true;\n";
    let locked = HashMap::from([(requested.to_string(), integrity(bytes))]);

    verify_graph_module_integrity(
        bytes,
        &requested,
        &effective,
        false,
        &root,
        Some(&integrity(b"root")),
        Some(&locked),
    )
    .unwrap();
}

#[test]
fn redirected_graph_accepts_effective_only_lockfile_binding() {
    let root = Url::parse("https://example.test/root.ts").unwrap();
    let requested = Url::parse("https://example.test/child.ts").unwrap();
    let effective = Url::parse("https://example.test/v1/child.ts").unwrap();
    let bytes = b"export const safe = true;\n";
    let locked = HashMap::from([(effective.to_string(), integrity(bytes))]);

    verify_graph_module_integrity(
        bytes,
        &requested,
        &effective,
        false,
        &root,
        Some(&integrity(b"root")),
        Some(&locked),
    )
    .unwrap();
}

#[test]
fn redirected_graph_rejects_conflicting_lockfile_bindings() {
    let root = Url::parse("https://example.test/root.ts").unwrap();
    let requested = Url::parse("https://example.test/child.ts").unwrap();
    let effective = Url::parse("https://example.test/v1/child.ts").unwrap();
    let bytes = b"export const safe = true;\n";
    let locked = HashMap::from([
        (requested.to_string(), integrity(bytes)),
        (effective.to_string(), integrity(b"different content")),
    ]);

    let error = verify_graph_module_integrity(
        bytes,
        &requested,
        &effective,
        false,
        &root,
        Some(&integrity(b"root")),
        Some(&locked),
    )
    .unwrap_err();

    assert!(error.to_string().contains("integrity verification failed"));
    assert!(error.to_string().contains(effective.as_str()));
}

#[test]
fn verify_graph_module_integrity_from_digest_matches_sha256_and_defers_sha512() {
    let root = Url::parse("https://example.test/root.ts").unwrap();
    let requested = Url::parse("https://example.test/child.ts").unwrap();
    let effective = Url::parse("https://example.test/v1/child.ts").unwrap();
    let bytes = b"export const safe = true;\n";
    let digest = raw_sha256(bytes);

    // sha256 binding returns Ok(Some(())):
    let locked_sha256 = HashMap::from([(requested.to_string(), integrity(bytes))]);
    assert_eq!(
        verify_graph_module_integrity_from_digest(
            &digest,
            &requested,
            &effective,
            false,
            &root,
            Some(&integrity(b"root")),
            Some(&locked_sha256),
        )
        .unwrap(),
        Some(())
    );

    // sha512 binding returns Ok(None):
    let locked_sha512 = HashMap::from([(requested.to_string(), sha512_integrity(bytes))]);
    assert_eq!(
        verify_graph_module_integrity_from_digest(
            &digest,
            &requested,
            &effective,
            false,
            &root,
            Some(&integrity(b"root")),
            Some(&locked_sha512),
        )
        .unwrap(),
        None
    );

    // Mismatched sha256 binding fails closed with Fetch error:
    let locked_mismatch = HashMap::from([(requested.to_string(), integrity(b"different content"))]);
    let error = verify_graph_module_integrity_from_digest(
        &digest,
        &requested,
        &effective,
        false,
        &root,
        Some(&integrity(b"root")),
        Some(&locked_mismatch),
    )
    .unwrap_err();
    assert!(error.to_string().contains("integrity verification failed"));
}
