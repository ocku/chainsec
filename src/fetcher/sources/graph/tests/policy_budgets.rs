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
            let read = match stream.read(&mut request) {
                Ok(0) | Err(_) => continue,
                Ok(read) => read,
            };
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

#[tokio::test]
async fn graph_fetch_enforces_a_per_acquisition_request_limit() {
    let ((stop, requests, server), root_url, lockfile, root_integrity, root_certificate) =
        spawn_graph_registry(Duration::ZERO);
    let (_cache, mut fetcher) = graph_http_fetcher(root_certificate);
    fetcher.limits.max_network_requests = 2;
    let temporary = tempfile::tempdir().unwrap();
    let mut budget = fetcher.network_budget();

    let error = fetcher
        .fetch_deno_graph_with_budget(
            &root_url,
            temporary.path(),
            Some(&root_integrity),
            Some(&lockfile),
            &mut budget,
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
    let mut budget = fetcher.network_budget();

    let error = fetcher
        .fetch_deno_graph_with_budget(
            &root_url,
            temporary.path(),
            Some(&root_integrity),
            Some(&lockfile),
            &mut budget,
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
    assert!(requests.lock().unwrap().len() <= 2);
}

#[test]
fn cached_graph_rebuild_counts_redirects_against_extraction_limits() {
    let (cache, mut fetcher) = graph_fetcher();
    fetcher.limits.max_extracted_files = 3;
    let root = Url::parse("https://example.test/root.ts").unwrap();
    let alias_a = Url::parse("https://example.test/alias-a.ts").unwrap();
    let alias_b = Url::parse("https://example.test/alias-b.ts").unwrap();
    let effective = Url::parse("https://example.test/v1/module.ts").unwrap();
    let root_bytes = b"import \"./alias-a.ts\"; import \"./alias-b.ts\";\n";
    let module_bytes = b"export const safe = true;\n";
    let cached_source = cache.path().join("cached");
    write_cached_module(&cached_source, &root, root_bytes);
    write_cached_module(&cached_source, &effective, module_bytes);
    for alias in [&alias_a, &alias_b] {
        fs::write(
            cached_source.join(graph_redirect_filename(alias)),
            effective.as_str(),
        )
        .unwrap();
    }
    let temporary = cache.path().join("temporary");
    fs::create_dir(&temporary).unwrap();
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

    let error = fetcher
        .rebuild_cached_deno_graph(
            &root,
            &temporary,
            Some(&integrity(root_bytes)),
            Some(&snapshot),
            &cached_source,
        )
        .unwrap_err();

    assert!(matches!(
        error,
        Error::LimitExceeded { resource, limit }
            if resource == "extracted files" && limit == 3
    ));
}

#[test]
fn cached_graph_rebuild_enforces_module_limit_when_queuing_children() {
    let (cache, mut fetcher) = graph_fetcher();
    fetcher.limits.max_packages = 2;
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
