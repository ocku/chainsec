use super::*;
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use reqwest::redirect::Policy;
use rustls::{ServerConfig, ServerConnection, StreamOwned, pki_types::PrivateKeyDer};

fn integrity(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn lockfile_snapshot(contents: &str) -> DenoLockfileSnapshot {
    let value = serde_json::from_str(contents).unwrap();
    DenoLockfileSnapshot::from_lockfile(contents.as_bytes(), &value)
}

fn remote_snapshot(remote_integrities: HashMap<String, String>) -> DenoLockfileSnapshot {
    DenoLockfileSnapshot::from_remote_integrities("test", remote_integrities)
}

#[test]
fn graph_queue_deduplicates_requested_urls() {
    let child = Url::parse("https://example.test/child.ts").unwrap();
    let other = Url::parse("https://example.test/other.ts").unwrap();
    let mut queue = VecDeque::new();
    let mut queued = HashSet::new();

    enqueue_graph_modules(
        &mut queue,
        &mut queued,
        vec![child.clone(), child.clone(), other.clone(), child],
    );

    assert_eq!(
        queue.into_iter().collect::<Vec<_>>(),
        vec![Url::parse("https://example.test/child.ts").unwrap(), other,]
    );
}

#[test]
fn graph_queue_rejects_candidates_beyond_module_limit() {
    let root = Url::parse("https://example.test/root.ts").unwrap();
    let child = Url::parse("https://example.test/child.ts").unwrap();
    let overflow = Url::parse("https://example.test/overflow.ts").unwrap();
    let mut queue = VecDeque::from([root.clone()]);
    let mut queued = HashSet::from([canonical_graph_url(&root)]);

    enqueue_graph_module(&mut queue, &mut queued, child, 2).unwrap();
    let error = enqueue_graph_module(&mut queue, &mut queued, overflow, 2).unwrap_err();

    assert!(
        matches!(error, Error::LimitExceeded { resource, limit } if resource == "Deno graph modules" && limit == 2)
    );
    assert_eq!(queue.len(), 2);
    assert_eq!(queued.len(), 2);
}

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

type GraphRegistry = (
    Arc<AtomicBool>,
    Arc<Mutex<Vec<String>>>,
    thread::JoinHandle<()>,
);

fn spawn_graph_registry(
    response_delay: Duration,
) -> (
    GraphRegistry,
    Url,
    DenoLockfileSnapshot,
    String,
    reqwest::Certificate,
) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let parameters = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    let certificate = parameters.self_signed(&key_pair).unwrap();
    let root_certificate = reqwest::Certificate::from_der(certificate.der()).unwrap();
    let private_key = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.der().clone()], private_key)
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base_url = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let root_url = Url::parse(&format!("{base_url}/root.ts")).unwrap();
    let first_url = Url::parse(&format!("{base_url}/first.ts")).unwrap();
    let second_url = Url::parse(&format!("{base_url}/second.ts")).unwrap();
    let root = b"import \"./first.ts\"; import \"./second.ts\";\n".to_vec();
    let first = b"export const first = true;\n".to_vec();
    let second = b"export const second = true;\n".to_vec();
    let modules = HashMap::from([
        ("/root.ts".to_owned(), root.clone()),
        ("/first.ts".to_owned(), first.clone()),
        ("/second.ts".to_owned(), second.clone()),
    ]);
    let root_integrity = integrity(&root);
    let lockfile = remote_snapshot(HashMap::from([
        (root_url.to_string(), integrity(&root)),
        (first_url.to_string(), integrity(&first)),
        (second_url.to_string(), integrity(&second)),
    ]));
    let stop = Arc::new(AtomicBool::new(false));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let server_stop = Arc::clone(&stop);
    let server_requests = Arc::clone(&requests);
    let server = thread::spawn(move || {
        while !server_stop.load(Ordering::Relaxed) {
            let (stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("accept Deno graph request: {error}"),
            };
            stream.set_nonblocking(false).unwrap();
            let connection = ServerConnection::new(Arc::clone(&server_config)).unwrap();
            let mut stream = StreamOwned::new(connection, stream);
            let mut request = [0_u8; 4096];
            let read = stream.read(&mut request).unwrap();
            let path = String::from_utf8_lossy(&request[..read])
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/")
                .to_owned();
            server_requests.lock().unwrap().push(path.clone());
            thread::sleep(response_delay);
            let body = modules
                .get(&path)
                .map(Vec::as_slice)
                .unwrap_or(b"not found");
            let status = if modules.contains_key(&path) {
                "200 OK"
            } else {
                "404 Not Found"
            };
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(body);
        }
    });

    (
        (stop, requests, server),
        root_url,
        lockfile,
        root_integrity,
        root_certificate,
    )
}

fn graph_http_fetcher(
    root_certificate: reqwest::Certificate,
) -> (tempfile::TempDir, SourceFetcher) {
    let cache = tempfile::tempdir().unwrap();
    let policy = crate::fetcher::FetchPolicy {
        offline: false,
        allowed_hosts: vec!["localhost".to_owned()],
        ..crate::fetcher::FetchPolicy::default()
    };
    let mut fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        policy,
        crate::model::EngineLimits::default(),
    )
    .unwrap();
    fetcher.client = Some(
        reqwest::Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .add_root_certificate(root_certificate)
            .build()
            .unwrap(),
    );
    (cache, fetcher)
}

fn graph_fetcher() -> (tempfile::TempDir, SourceFetcher) {
    let cache = tempfile::tempdir().unwrap();
    let policy = crate::fetcher::FetchPolicy {
        allowed_hosts: vec!["example.test".to_owned()],
        ..crate::fetcher::FetchPolicy::default()
    };
    let fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        policy,
        crate::model::EngineLimits::default(),
    )
    .unwrap();
    (cache, fetcher)
}

#[tokio::test]
async fn graph_fetch_enforces_a_per_acquisition_request_limit() {
    let ((stop, requests, server), root_url, lockfile, root_integrity, root_certificate) =
        spawn_graph_registry(Duration::ZERO);
    let (_cache, mut fetcher) = graph_http_fetcher(root_certificate);
    fetcher.limits.max_network_requests = 2;
    let temporary = tempfile::tempdir().unwrap();

    let error = fetcher
        .fetch_deno_graph(
            &root_url,
            temporary.path(),
            Some(&root_integrity),
            Some(&lockfile),
        )
        .await
        .unwrap_err();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    assert_eq!(error.code(), "limit_exceeded", "{error}");
    assert!(
        error
            .to_string()
            .contains("network requests per package acquisition"),
        "{error}"
    );
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn graph_fetch_enforces_an_end_to_end_acquisition_deadline() {
    let ((stop, requests, server), root_url, lockfile, root_integrity, root_certificate) =
        spawn_graph_registry(Duration::from_millis(40));
    let (_cache, mut fetcher) = graph_http_fetcher(root_certificate);
    fetcher.limits.max_acquisition_duration = Duration::from_millis(70);
    let temporary = tempfile::tempdir().unwrap();

    let error = fetcher
        .fetch_deno_graph(
            &root_url,
            temporary.path(),
            Some(&root_integrity),
            Some(&lockfile),
        )
        .await
        .unwrap_err();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    assert_eq!(error.code(), "limit_exceeded", "{error}");
    assert!(
        error.to_string().contains("package acquisition seconds"),
        "{error}"
    );
    assert_eq!(requests.lock().unwrap().len(), 2);
}

fn write_cached_module(source: &Path, url: &Url, bytes: &[u8]) {
    fs::create_dir_all(source).unwrap();
    let filename = format!(
        "{}.{}",
        hex::encode(Sha256::digest(canonical_graph_url(url).as_bytes())),
        module_extension(url)
    );
    fs::write(source.join(filename), bytes).unwrap();
}

#[test]
fn graph_resolution_rejects_unmaterialized_registry_specifiers() {
    let base = Url::parse("https://example.test/root.ts").unwrap();

    for specifier in ["npm:package@1.0.0", "jsr:@scope/package@1.0.0"] {
        let error = resolve_graph_modules(&base, format!("import {specifier:?};").as_bytes(), "ts")
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("Deno graph resolution"));
        assert!(message.contains(specifier));
        assert!(message.contains("https://example.test/root.ts"));
        assert!(message.contains("incomplete"));
    }
}

#[test]
fn graph_resolution_rejects_unsupported_dynamic_imports() {
    let base = Url::parse("https://example.test/root.ts").unwrap();

    let error =
        resolve_graph_modules(&base, b"await import(\"npm:package@1.0.0\");", "ts").unwrap_err();

    assert!(error.to_string().contains("npm:package@1.0.0"));
    assert!(error.to_string().contains("incomplete"));
}

#[test]
fn graph_resolution_rejects_other_unsupported_static_literals() {
    let base = Url::parse("https://example.test/root.ts").unwrap();

    for specifier in [
        "node:fs",
        "data:text/javascript,export{}",
        "package",
        "loader:package",
    ] {
        let error = resolve_graph_modules(&base, format!("import {specifier:?};").as_bytes(), "ts")
            .unwrap_err();
        assert!(error.to_string().contains(specifier));
        assert!(error.to_string().contains("incomplete"));
    }

    let error = resolve_graph_modules(&base, b"import \"./%\";", "ts").unwrap_err();
    assert!(error.to_string().contains("invalid"));
    assert!(error.to_string().contains("incomplete"));
}

#[test]
fn graph_resolution_retains_http_and_url_relative_modules() {
    let base = Url::parse("https://example.test/path/root.ts").unwrap();

    let modules = resolve_graph_modules(
        &base,
        b"import \"https://cdn.example.test/module.ts\"; import \"./child.ts\";",
        "ts",
    )
    .unwrap();

    assert_eq!(
        modules,
        [
            Url::parse("https://cdn.example.test/module.ts").unwrap(),
            Url::parse("https://example.test/path/child.ts").unwrap(),
        ]
    );
}

#[test]
fn graph_resolution_decodes_escaped_static_specifiers() {
    let base = Url::parse("https://example.test/path/root.ts").unwrap();

    let modules = resolve_graph_modules(
            &base,
            br#"import "./\x65vil.ts"; export { value } from "./\u0065xport.ts"; await import("./d\u{79}namic.ts");"#,
            "ts",
        )
        .unwrap();

    assert_eq!(
        modules,
        [
            Url::parse("https://example.test/path/evil.ts").unwrap(),
            Url::parse("https://example.test/path/export.ts").unwrap(),
            Url::parse("https://example.test/path/dynamic.ts").unwrap(),
        ]
    );
}

#[test]
fn graph_resolution_decodes_escaped_url_characters() {
    let base = Url::parse("https://example.test/root.ts").unwrap();

    let modules = resolve_graph_modules(
        &base,
        br#"import "https:\u002f\u002fcdn.example.test\u002fmodule.ts";"#,
        "ts",
    )
    .unwrap();

    assert_eq!(
        modules,
        [Url::parse("https://cdn.example.test/module.ts").unwrap()]
    );
}

#[test]
fn graph_resolution_rejects_malformed_escaped_specifiers() {
    let base = Url::parse("https://example.test/root.ts").unwrap();

    for source in [
        br#"import "./\x6";"#.as_slice(),
        br#"import "./\u{110000}.ts";"#.as_slice(),
    ] {
        let error = resolve_graph_modules(&base, source, "ts").unwrap_err();
        let message = error.to_string();
        assert!(message.contains("https://example.test/root.ts"));
        assert!(message.contains("decode"));
        assert!(message.contains("incomplete"));
    }
}

#[test]
fn nonliteral_dynamic_import_is_not_collected() {
    let base = Url::parse("https://example.test/root.ts").unwrap();

    assert!(
        resolve_graph_modules(&base, b"await import(module_name);", "ts")
            .unwrap()
            .is_empty()
    );
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
fn cached_redirected_graph_accepts_requested_binding_and_uses_effective_import_base() {
    let (temporary, fetcher) = graph_fetcher();
    let cached_source = temporary.path().join("cached");
    let output = temporary.path().join("output");
    fs::create_dir_all(&cached_source).unwrap();
    fs::create_dir_all(&output).unwrap();

    let requested = Url::parse("https://example.test/root.ts").unwrap();
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
    let snapshot = remote_snapshot(remote_integrities);

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
    assert_eq!(stats.files, 2);
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
    let snapshot = remote_snapshot(HashMap::from([
        (requested.to_string(), integrity(root_bytes)),
        (effective.to_string(), integrity(b"different content")),
    ]));

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
    let snapshot = remote_snapshot(HashMap::from([
        (root.to_string(), integrity(root_bytes)),
        (alias_a.to_string(), integrity(module_bytes)),
        (alias_b.to_string(), integrity(b"conflicting alias content")),
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
    let snapshot = remote_snapshot(HashMap::from([
        (root.to_string(), integrity(root_bytes)),
        (alias_a.to_string(), integrity(module_bytes)),
        (alias_b.to_string(), integrity(module_bytes)),
    ]));

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
    assert_eq!(stats.files, 2);
    assert_eq!(stats.bytes, (root_bytes.len() + module_bytes.len()) as u64);
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
fn cached_graph_rebuild_enforces_module_limit_when_queuing_children() {
    let (cache, mut fetcher) = graph_fetcher();
    fetcher.policy.max_deno_modules = 2;
    let root = Url::parse("https://example.test/root.ts").unwrap();
    let first = Url::parse("https://example.test/first.ts").unwrap();
    let second = Url::parse("https://example.test/second.ts").unwrap();
    let root_bytes = b"import './first.ts'; import './second.ts';\n";
    let first_bytes = b"export const first = true;\n";
    let second_bytes = b"export const second = true;\n";
    let cached_source = cache.path().join("cached");
    write_cached_module(&cached_source, &root, root_bytes);
    write_cached_module(&cached_source, &first, first_bytes);
    write_cached_module(&cached_source, &second, second_bytes);
    let temporary = cache.path().join("temporary");
    fs::create_dir(&temporary).unwrap();
    let lockfile = remote_snapshot(HashMap::from([
        (root.to_string(), integrity(root_bytes)),
        (first.to_string(), integrity(first_bytes)),
        (second.to_string(), integrity(second_bytes)),
    ]));

    let error = fetcher
        .rebuild_cached_deno_graph(
            &root,
            &temporary,
            Some(&integrity(root_bytes)),
            Some(&lockfile),
            &cached_source,
        )
        .unwrap_err();

    assert!(matches!(
        error,
        Error::LimitExceeded { resource, limit }
            if resource == "Deno graph modules" && limit == 2
    ));
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
