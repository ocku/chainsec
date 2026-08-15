use super::*;

#[cfg(unix)]
#[test]
fn cached_graph_fifo_is_rejected_without_blocking() {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};

    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("cached");
    fs::create_dir(&source).unwrap();
    let filename = "module.ts";
    let fifo = source.join(filename);
    let fifo = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: the CString is a valid, NUL-terminated filesystem path.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

    let root = TrustedDir::open(&source).unwrap();
    assert!(matches!(
        read_cached_graph_module(&root, &source, filename, 1024),
        Err(Error::Policy { operation, .. }) if operation == "cache validation"
    ));
}

#[test]
fn cached_root_redirect_rejects_an_unallowed_cross_origin_effective_url() {
    let (temporary, fetcher) = graph_fetcher();
    let cached_source = temporary.path().join("cached");
    let output = temporary.path().join("output");
    fs::create_dir_all(&cached_source).unwrap();
    fs::create_dir_all(&output).unwrap();

    // Cached roots bypass host revalidation, but redirect targets do not gain
    // that exemption when they cross origins.
    let requested = Url::parse("https://stale-root.test/root.ts").unwrap();
    let effective = Url::parse("https://unallowed.test/root.ts").unwrap();
    let root_bytes = b"export const safe = true;\n";
    write_cached_module(&cached_source, &effective, root_bytes);
    fs::write(
        cached_source.join(graph_redirect_filename(&requested)),
        effective.as_str(),
    )
    .unwrap();
    let snapshot = remote_snapshot_with_redirects(
        HashMap::from([(requested.to_string(), integrity(root_bytes))]),
        HashMap::from([(requested.to_string(), effective.to_string())]),
    );

    let error = fetcher
        .rebuild_cached_deno_graph(
            &requested,
            &output,
            Some(&integrity(root_bytes)),
            Some(&snapshot),
            &cached_source,
        )
        .unwrap_err();

    assert!(error.to_string().contains("unallowed.test"), "{error}");
    assert!(error.to_string().contains("allowlist"), "{error}");
}

#[test]
fn cached_graph_rebuild_rejects_unallowed_import_hosts() {
    let (temporary, fetcher) = graph_fetcher();
    let cached_source = temporary.path().join("cached");
    let output = temporary.path().join("output");
    fs::create_dir_all(&output).unwrap();

    let root = Url::parse("https://example.test/root.ts").unwrap();
    let unallowed = Url::parse("https://unallowed.test/child.ts").unwrap();
    let root_bytes = b"import \"https://unallowed.test/child.ts\";\n";
    let child_bytes = b"export const safe = true;\n";
    write_cached_module(&cached_source, &root, root_bytes);
    write_cached_module(&cached_source, &unallowed, child_bytes);
    let snapshot = remote_snapshot(HashMap::from([
        (root.to_string(), integrity(root_bytes)),
        (unallowed.to_string(), integrity(child_bytes)),
    ]));

    let error = fetcher
        .rebuild_cached_deno_graph(
            &root,
            &output,
            Some(&integrity(root_bytes)),
            Some(&snapshot),
            &cached_source,
        )
        .unwrap_err();

    assert!(error.to_string().contains("unallowed.test"));
    assert!(error.to_string().contains("allowlist"));
}

#[test]
fn cached_redirected_graph_rejects_conflicting_lockfile_bindings() {
    let (temporary, fetcher) = graph_fetcher();
    let cached_source = temporary.path().join("cached");
    let output = temporary.path().join("output");
    fs::create_dir_all(&cached_source).unwrap();
    fs::create_dir_all(&output).unwrap();

    let requested = Url::parse("https://example.test/root.ts").unwrap();
    let effective = Url::parse("https://example.test/v1/root.ts").unwrap();
    let root_bytes = b"export const safe = true;\n";
    write_cached_module(&cached_source, &effective, root_bytes);
    fs::write(
        cached_source.join(graph_redirect_filename(&requested)),
        effective.as_str(),
    )
    .unwrap();
    let snapshot = remote_snapshot_with_redirects(
        HashMap::from([
            (requested.to_string(), integrity(root_bytes)),
            (effective.to_string(), integrity(b"different content")),
        ]),
        HashMap::from([(requested.to_string(), effective.to_string())]),
    );

    let error = fetcher
        .rebuild_cached_deno_graph(
            &requested,
            &output,
            Some(&integrity(root_bytes)),
            Some(&snapshot),
            &cached_source,
        )
        .unwrap_err();

    assert!(error.to_string().contains("integrity verification failed"));
    assert!(error.to_string().contains(effective.as_str()));
}

#[test]
fn cached_aliases_to_one_effective_module_all_validate_requested_integrity() {
    let (temporary, fetcher) = graph_fetcher();
    let cached_source = temporary.path().join("cached");
    let output = temporary.path().join("output");
    fs::create_dir_all(&cached_source).unwrap();
    fs::create_dir_all(&output).unwrap();

    let root = Url::parse("https://example.test/root.ts").unwrap();
    let alias_a = Url::parse("https://example.test/alias-a.ts").unwrap();
    let alias_b = Url::parse("https://example.test/alias-b.ts").unwrap();
    let effective = Url::parse("https://example.test/v1/module.ts").unwrap();
    let root_bytes = b"import \"./alias-a.ts\"; import \"./alias-b.ts\";\n";
    let module_bytes = b"export const safe = true;\n";
    write_cached_module(&cached_source, &root, root_bytes);
    write_cached_module(&cached_source, &effective, module_bytes);
    for alias in [&alias_a, &alias_b] {
        fs::write(
            cached_source.join(graph_redirect_filename(alias)),
            effective.as_str(),
        )
        .unwrap();
    }
    let snapshot = remote_snapshot_with_redirects(
        HashMap::from([
            (root.to_string(), integrity(root_bytes)),
            (alias_a.to_string(), integrity(module_bytes)),
            (alias_b.to_string(), integrity(b"conflicting alias content")),
        ]),
        HashMap::from([
            (alias_a.to_string(), effective.to_string()),
            (alias_b.to_string(), effective.to_string()),
        ]),
    );

    let error = fetcher
        .rebuild_cached_deno_graph(
            &root,
            &output,
            Some(&integrity(root_bytes)),
            Some(&snapshot),
            &cached_source,
        )
        .unwrap_err();

    assert!(error.to_string().contains("integrity verification failed"));
    assert!(error.to_string().contains(alias_b.as_str()));
}

#[test]
fn cached_aliases_to_one_effective_module_reconstruct_once_with_all_redirects() {
    let (temporary, fetcher) = graph_fetcher();
    let cached_source = temporary.path().join("cached");
    let output = temporary.path().join("output");
    fs::create_dir_all(&cached_source).unwrap();
    fs::create_dir_all(&output).unwrap();

    let root = Url::parse("https://example.test/root.ts").unwrap();
    let alias_a = Url::parse("https://example.test/alias-a.ts").unwrap();
    let alias_b = Url::parse("https://example.test/alias-b.ts").unwrap();
    let effective = Url::parse("https://example.test/v1/module.ts").unwrap();
    let root_bytes = b"import \"./alias-a.ts\"; import \"./alias-b.ts\";\n";
    let module_bytes = b"export const safe = true;\n";
    write_cached_module(&cached_source, &root, root_bytes);
    write_cached_module(&cached_source, &effective, module_bytes);
    for alias in [&alias_a, &alias_b] {
        fs::write(
            cached_source.join(graph_redirect_filename(alias)),
            effective.as_str(),
        )
        .unwrap();
    }
    let snapshot = remote_snapshot_with_redirects(
        HashMap::from([
            (root.to_string(), integrity(root_bytes)),
            (alias_a.to_string(), integrity(module_bytes)),
            (alias_b.to_string(), integrity(module_bytes)),
        ]),
        HashMap::from([
            (alias_a.to_string(), effective.to_string()),
            (alias_b.to_string(), effective.to_string()),
        ]),
    );

    let (source, digest, stats) = fetcher
        .rebuild_cached_deno_graph(
            &root,
            &output,
            Some(&integrity(root_bytes)),
            Some(&snapshot),
            &cached_source,
        )
        .unwrap();

    assert_eq!(digest, integrity(root_bytes));
    assert_eq!(stats.files, 4);
    assert_eq!(
        stats.bytes,
        (root_bytes.len() + module_bytes.len() + 2 * effective.as_str().len()) as u64
    );
    for alias in [&alias_a, &alias_b] {
        assert_eq!(
            fs::read_to_string(source.join(graph_redirect_filename(alias))).unwrap(),
            effective.as_str()
        );
    }
    assert_eq!(fs::read_dir(source).unwrap().count(), 4);
}

#[test]
fn cached_root_only_graph_is_rebuilt_from_root_integrity() {
    let (cache, fetcher) = graph_fetcher();
    let root = Url::parse("https://example.test/root.ts").unwrap();
    let cached_source = cache.path().join("cached");
    write_cached_module(&cached_source, &root, b"export const safe = true;\n");
    let temporary = cache.path().join("temporary");
    fs::create_dir(&temporary).unwrap();

    let (source, _, stats) = fetcher
        .rebuild_cached_deno_graph(
            &root,
            &temporary,
            Some(&integrity(b"export const safe = true;\n")),
            None,
            &cached_source,
        )
        .unwrap();

    assert_eq!(stats.files, 1);
    assert_eq!(fs::read_dir(source).unwrap().count(), 1);
}

#[test]
fn cached_graph_rebuild_decodes_escaped_specifiers_and_checks_child_integrity() {
    let (cache, fetcher) = graph_fetcher();
    let root = Url::parse("https://example.test/root.ts").unwrap();
    let child = Url::parse("https://example.test/child.ts").unwrap();
    let root_bytes = br#"import "./\x63hild.ts";"#;
    let child_bytes = b"export const scanned_child = true;\n";
    let cached_source = cache.path().join("cached");
    write_cached_module(&cached_source, &root, root_bytes);
    write_cached_module(&cached_source, &child, child_bytes);
    let temporary = cache.path().join("temporary");
    fs::create_dir(&temporary).unwrap();
    let lockfile = remote_snapshot(HashMap::from([
        (root.to_string(), integrity(root_bytes)),
        (child.to_string(), integrity(child_bytes)),
    ]));

    let (source, _, stats) = fetcher
        .rebuild_cached_deno_graph(
            &root,
            &temporary,
            Some(&integrity(root_bytes)),
            Some(&lockfile),
            &cached_source,
        )
        .unwrap();

    assert_eq!(stats.files, 2);
    assert_eq!(fs::read_dir(source).unwrap().count(), 2);
}

#[test]
fn cached_graph_children_without_lock_integrity_are_rejected() {
    let (cache, fetcher) = graph_fetcher();
    let root = Url::parse("https://example.test/root.ts").unwrap();
    let child = Url::parse("https://example.test/child.ts").unwrap();
    let root_bytes = b"import './child.ts';\n";
    let cached_source = cache.path().join("cached");
    write_cached_module(&cached_source, &root, root_bytes);
    write_cached_module(&cached_source, &child, b"export const child = true;\n");
    let temporary = cache.path().join("temporary");
    fs::create_dir(&temporary).unwrap();

    let error = fetcher
        .rebuild_cached_deno_graph(
            &root,
            &temporary,
            Some(&integrity(root_bytes)),
            None,
            &cached_source,
        )
        .unwrap_err();

    assert!(error.to_string().contains("no lockfile integrity binding"));
}

#[test]
fn cached_aliases_repeat_encounter_with_sha512_binding_verifies_successfully() {
    let (temporary, fetcher) = graph_fetcher();
    let cached_source = temporary.path().join("cached");
    let output = temporary.path().join("output");
    fs::create_dir_all(&cached_source).unwrap();
    fs::create_dir_all(&output).unwrap();

    let root = Url::parse("https://example.test/root.ts").unwrap();
    let alias_a = Url::parse("https://example.test/alias-a.ts").unwrap();
    let alias_b = Url::parse("https://example.test/alias-b.ts").unwrap();
    let effective = Url::parse("https://example.test/v1/module.ts").unwrap();
    let root_bytes = b"import \"./alias-a.ts\"; import \"./alias-b.ts\";\n";
    let module_bytes = b"export const safe = true;\n";
    write_cached_module(&cached_source, &root, root_bytes);
    write_cached_module(&cached_source, &effective, module_bytes);
    for alias in [&alias_a, &alias_b] {
        fs::write(
            cached_source.join(graph_redirect_filename(alias)),
            effective.as_str(),
        )
        .unwrap();
    }
    let snapshot = remote_snapshot_with_redirects(
        HashMap::from([
            (root.to_string(), integrity(root_bytes)),
            (alias_a.to_string(), integrity(module_bytes)),
            (alias_b.to_string(), sha512_integrity(module_bytes)),
        ]),
        HashMap::from([
            (alias_a.to_string(), effective.to_string()),
            (alias_b.to_string(), effective.to_string()),
        ]),
    );

    let (source, digest, stats) = fetcher
        .rebuild_cached_deno_graph(
            &root,
            &output,
            Some(&integrity(root_bytes)),
            Some(&snapshot),
            &cached_source,
        )
        .unwrap();

    assert_eq!(digest, integrity(root_bytes));
    assert_eq!(stats.files, 4);
    assert_eq!(
        stats.bytes,
        (root_bytes.len() + module_bytes.len() + 2 * effective.as_str().len()) as u64
    );
    for alias in [&alias_a, &alias_b] {
        assert_eq!(
            fs::read_to_string(source.join(graph_redirect_filename(alias))).unwrap(),
            effective.as_str()
        );
    }
    assert_eq!(fs::read_dir(source).unwrap().count(), 4);
}

#[test]
fn tamper_evidence_rejects_modified_materialized_file_on_sha512_repeat() {
    let temporary = tempfile::tempdir().unwrap();
    let source_dir = temporary.path().join("source");
    fs::create_dir_all(&source_dir).unwrap();
    let source_root = TrustedDir::open(&source_dir).unwrap();

    let root_url = Url::parse("https://example.test/root.ts").unwrap();
    let alias_url = Url::parse("https://example.test/alias.ts").unwrap();
    let effective_url = Url::parse("https://example.test/v1/module.ts").unwrap();

    let original_bytes = b"export const safe = true;\n";
    let canonical = canonical_graph_url(&effective_url);
    let deadline = crate::fetcher::budget::AcquisitionBudget::new(
        std::time::Duration::from_secs(3_600),
        u64::MAX,
    )
    .deadline_guard();
    let stored_digest = sha256_digest_raw_before(original_bytes, &deadline).unwrap();

    let filename = cached_graph_module_filename(&canonical, module_extension(&effective_url));
    fs::write(source_dir.join(&filename), original_bytes).unwrap();

    let binding_map = HashMap::from([(alias_url.to_string(), sha512_integrity(original_bytes))]);
    let binding = GraphIntegrity {
        requested_url: &alias_url,
        effective_url: &effective_url,
        is_root: false,
        root_url: &root_url,
        expected: None,
        remote_integrities: Some(&binding_map),
    };

    // Original file passes tamper-check and sha512 verification:
    verify_materialized_module_bytes(
        &source_root,
        &source_dir,
        &canonical,
        1024 * 1024,
        &stored_digest,
        binding,
        &deadline,
    )
    .unwrap();

    // Tampered file is rejected on tamper-evidence check before trusting the bytes:
    fs::write(
        source_dir.join(&filename),
        b"export const tampered = true;\n",
    )
    .unwrap();

    let error = verify_materialized_module_bytes(
        &source_root,
        &source_dir,
        &canonical,
        1024 * 1024,
        &stored_digest,
        binding,
        &deadline,
    )
    .unwrap_err();

    assert!(error.to_string().contains("integrity verification failed"));
}

#[test]
fn cached_repeat_encounter_with_conflicting_sha256_binding_is_rejected() {
    let (temporary, fetcher) = graph_fetcher();
    let cached_source = temporary.path().join("cached");
    let output = temporary.path().join("output");
    fs::create_dir_all(&cached_source).unwrap();
    fs::create_dir_all(&output).unwrap();

    let root = Url::parse("https://example.test/root.ts").unwrap();
    let alias_a = Url::parse("https://example.test/alias-a.ts").unwrap();
    let alias_b = Url::parse("https://example.test/alias-b.ts").unwrap();
    let effective = Url::parse("https://example.test/v1/module.ts").unwrap();
    let root_bytes = b"import \"./alias-a.ts\"; import \"./alias-b.ts\";\n";
    let module_bytes = b"export const safe = true;\n";
    write_cached_module(&cached_source, &root, root_bytes);
    write_cached_module(&cached_source, &effective, module_bytes);
    for alias in [&alias_a, &alias_b] {
        fs::write(
            cached_source.join(graph_redirect_filename(alias)),
            effective.as_str(),
        )
        .unwrap();
    }
    let snapshot = remote_snapshot_with_redirects(
        HashMap::from([
            (root.to_string(), integrity(root_bytes)),
            (alias_a.to_string(), integrity(module_bytes)),
            (alias_b.to_string(), integrity(b"conflicting content")),
        ]),
        HashMap::from([
            (alias_a.to_string(), effective.to_string()),
            (alias_b.to_string(), effective.to_string()),
        ]),
    );

    let error = fetcher
        .rebuild_cached_deno_graph(
            &root,
            &output,
            Some(&integrity(root_bytes)),
            Some(&snapshot),
            &cached_source,
        )
        .unwrap_err();

    assert!(error.to_string().contains("integrity verification failed"));
    assert!(error.to_string().contains(alias_b.as_str()));
}
