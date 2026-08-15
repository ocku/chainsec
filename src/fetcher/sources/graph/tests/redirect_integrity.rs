use super::*;

#[test]
fn cached_redirected_graph_accepts_requested_binding_and_uses_effective_import_base() {
    let (temporary, fetcher) = graph_fetcher();
    let cached_source = temporary.path().join("cached");
    let output = temporary.path().join("output");
    fs::create_dir_all(&cached_source).unwrap();
    fs::create_dir_all(&output).unwrap();

    let requested = Url::parse("https://example.test/root.ts").unwrap();
    let intermediate = Url::parse("https://example.test/redirect/root.ts").unwrap();
    let effective = Url::parse("https://example.test/v1/root.ts").unwrap();
    let child = Url::parse("https://example.test/v1/child.ts").unwrap();
    let root_bytes = b"import \"./child.ts\";\n";
    let child_bytes = b"export const safe = true;\n";
    write_cached_module(&cached_source, &effective, root_bytes);
    write_cached_module(&cached_source, &child, child_bytes);
    fs::write(
        cached_source.join(graph_redirect_filename(&requested)),
        effective.as_str(),
    )
    .unwrap();

    let mut remote_integrities = HashMap::new();
    remote_integrities.insert(requested.to_string(), integrity(root_bytes));
    remote_integrities.insert(child.to_string(), integrity(child_bytes));
    let snapshot = remote_snapshot_with_redirects(
        remote_integrities,
        HashMap::from([
            (requested.to_string(), intermediate.to_string()),
            (intermediate.to_string(), effective.to_string()),
        ]),
    );

    let (_, digest, stats) = fetcher
        .rebuild_cached_deno_graph(
            &requested,
            &output,
            Some(&integrity(root_bytes)),
            Some(&snapshot),
            &cached_source,
        )
        .unwrap();

    assert_eq!(digest, integrity(root_bytes));
    assert_eq!(stats.files, 3);
    assert_eq!(
        stats.bytes,
        (root_bytes.len() + child_bytes.len() + effective.as_str().len()) as u64
    );
}

#[test]
fn cached_graph_rejects_an_undeclared_redirect() {
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
    let snapshot = remote_snapshot(HashMap::from([(
        requested.to_string(),
        integrity(root_bytes),
    )]));

    let error = fetcher
        .rebuild_cached_deno_graph(
            &requested,
            &output,
            Some(&integrity(root_bytes)),
            Some(&snapshot),
            &cached_source,
        )
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("is not declared by the lockfile")
    );
}

#[test]
fn cached_graph_rejects_a_mutated_declared_redirect() {
    let (temporary, fetcher) = graph_fetcher();
    let cached_source = temporary.path().join("cached");
    let valid_output = temporary.path().join("valid-output");
    let mutated_output = temporary.path().join("mutated-output");
    fs::create_dir_all(&cached_source).unwrap();
    fs::create_dir_all(&valid_output).unwrap();
    fs::create_dir_all(&mutated_output).unwrap();

    let requested = Url::parse("https://example.test/root.ts").unwrap();
    let locked_effective = Url::parse("https://example.test/v1/root.ts").unwrap();
    let locked_child = Url::parse("https://example.test/v1/child.ts").unwrap();
    let mutated_effective = Url::parse("https://example.test/unrelated/root.ts").unwrap();
    let unrelated_child = Url::parse("https://example.test/unrelated/child.ts").unwrap();
    let root_bytes = b"import \"./child.ts\";\n";
    let locked_child_bytes = b"export const expected = true;\n";
    let unrelated_child_bytes = b"export const unrelated = true;\n";
    write_cached_module(&cached_source, &locked_effective, root_bytes);
    write_cached_module(&cached_source, &locked_child, locked_child_bytes);
    write_cached_module(&cached_source, &mutated_effective, root_bytes);
    write_cached_module(&cached_source, &unrelated_child, unrelated_child_bytes);
    let redirect_path = cached_source.join(graph_redirect_filename(&requested));
    fs::write(&redirect_path, locked_effective.as_str()).unwrap();
    let snapshot = remote_snapshot_with_redirects(
        HashMap::from([
            (requested.to_string(), integrity(root_bytes)),
            (locked_child.to_string(), integrity(locked_child_bytes)),
            (
                unrelated_child.to_string(),
                integrity(unrelated_child_bytes),
            ),
        ]),
        HashMap::from([(requested.to_string(), locked_effective.to_string())]),
    );

    fetcher
        .rebuild_cached_deno_graph(
            &requested,
            &valid_output,
            Some(&integrity(root_bytes)),
            Some(&snapshot),
            &cached_source,
        )
        .unwrap();

    fs::write(&redirect_path, mutated_effective.as_str()).unwrap();
    let error = fetcher
        .rebuild_cached_deno_graph(
            &requested,
            &mutated_output,
            Some(&integrity(root_bytes)),
            Some(&snapshot),
            &cached_source,
        )
        .unwrap_err();

    let message = error.to_string();
    assert!(message.contains("does not match lockfile effective URL"));
    assert!(message.contains(mutated_effective.as_str()));
    assert!(message.contains(locked_effective.as_str()));
}

#[test]
fn cached_graph_rejects_a_missing_declared_redirect() {
    let (temporary, fetcher) = graph_fetcher();
    let cached_source = temporary.path().join("cached");
    let output = temporary.path().join("output");
    fs::create_dir_all(&output).unwrap();

    let requested = Url::parse("https://example.test/root.ts").unwrap();
    let effective = Url::parse("https://example.test/v1/root.ts").unwrap();
    let root_bytes = b"export const safe = true;\n";
    write_cached_module(&cached_source, &requested, root_bytes);
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

    assert!(error.to_string().contains("cached Deno redirect"));
    assert!(error.to_string().contains("is missing"));
    assert!(error.to_string().contains(effective.as_str()));
}
