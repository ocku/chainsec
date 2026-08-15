use super::*;

pub(super) type JsrRegistry = (
    String,
    Arc<AtomicBool>,
    Arc<Mutex<Vec<(String, String)>>>,
    thread::JoinHandle<()>,
);

pub(super) type RedirectingJsrRegistry = (
    String,
    Arc<AtomicBool>,
    Arc<Mutex<Vec<(String, bool)>>>,
    thread::JoinHandle<()>,
);

pub(super) fn spawn_jsr_registry(
    package_metadata: JsonValue,
    unavailable_versions: &[&str],
    malformed_versions: &[&str],
) -> JsrRegistry {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let package_metadata = package_metadata.to_string().into_bytes();
    let unavailable_versions = unavailable_versions
        .iter()
        .map(|version| format!("/{version}_meta.json"))
        .collect::<HashSet<_>>();
    let malformed_versions = malformed_versions
        .iter()
        .map(|version| format!("/{version}_meta.json"))
        .collect::<HashSet<_>>();
    let stop = Arc::new(AtomicBool::new(false));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let server_stop = Arc::clone(&stop);
    let server_requests = Arc::clone(&requests);
    let server = thread::spawn(move || {
        while !server_stop.load(Ordering::Relaxed) {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("accept JSR registry request: {error}"),
            };
            stream.set_nonblocking(false).unwrap();
            let mut request = [0_u8; 4096];
            let read = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            let path = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/")
                .to_owned();
            server_requests
                .lock()
                .unwrap()
                .push((path.clone(), request.into_owned()));
            let unavailable = unavailable_versions
                .iter()
                .any(|suffix| path.ends_with(suffix));
            let malformed = malformed_versions
                .iter()
                .any(|suffix| path.ends_with(suffix));
            let (status, body) = if path.ends_with("/meta.json") {
                ("200 OK", package_metadata.as_slice())
            } else if unavailable {
                ("404 Not Found", b"not found".as_slice())
            } else if malformed {
                ("200 OK", b"not valid JSON".as_slice())
            } else {
                ("200 OK", br#"{"manifest":{}}"#.as_slice())
            };
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        }
    });

    (base_url, stop, requests, server)
}

pub(super) fn spawn_jsr_package_registry(
    files: &[(&str, &[u8])],
    response_delay: Duration,
) -> (JsrRegistry, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let manifest = files
        .iter()
        .map(|(path, bytes)| {
            (
                format!("/{path}"),
                serde_json::json!({
                    "size": bytes.len(),
                    "checksum": format!("sha256-{}", hex::encode(Sha256::digest(bytes))),
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let metadata = serde_json::to_vec(&serde_json::json!({ "manifest": manifest })).unwrap();
    let integrity = format!("sha256:{}", hex::encode(Sha256::digest(&metadata)));
    let files = files
        .iter()
        .map(|(path, bytes)| (format!("/{path}"), bytes.to_vec()))
        .collect::<std::collections::HashMap<_, _>>();
    let stop = Arc::new(AtomicBool::new(false));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let server_stop = Arc::clone(&stop);
    let server_requests = Arc::clone(&requests);
    let server = thread::spawn(move || {
        while !server_stop.load(Ordering::Relaxed) {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("accept JSR package request: {error}"),
            };
            stream.set_nonblocking(false).unwrap();
            let mut request = [0_u8; 4096];
            let read = stream.read(&mut request).unwrap();
            let path = String::from_utf8_lossy(&request[..read])
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/")
                .to_owned();
            server_requests.lock().unwrap().push((
                path.clone(),
                String::from_utf8_lossy(&request[..read]).into_owned(),
            ));
            thread::sleep(response_delay);
            let body = if path.ends_with("_meta.json") {
                metadata.as_slice()
            } else {
                files
                    .iter()
                    .find_map(|(suffix, bytes)| path.ends_with(suffix).then_some(bytes.as_slice()))
                    .unwrap_or(b"not found")
            };
            let status = if path.ends_with("_meta.json")
                || files.keys().any(|suffix| path.ends_with(suffix))
            {
                "200 OK"
            } else {
                "404 Not Found"
            };
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        }
    });
    ((base_url, stop, requests, server), integrity)
}

pub(super) fn spawn_redirecting_jsr_registry(source_bytes: &[u8]) -> RedirectingJsrRegistry {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}");
    let effective_base_url = format!("http://localhost:{port}");
    let effective_metadata_path = "/cdn/releases/1.0.0_meta.json";
    let effective_file_path = "/cdn/releases/1.0.0/mod.ts";
    let checksum = format!("sha256-{}", hex::encode(Sha256::digest(source_bytes)));
    let metadata = serde_json::to_vec(&serde_json::json!({
        "manifest": {
            "/mod.ts": {
                "size": source_bytes.len(),
                "checksum": checksum,
            }
        }
    }))
    .unwrap();
    let source_bytes = source_bytes.to_vec();
    let stop = Arc::new(AtomicBool::new(false));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let server_stop = Arc::clone(&stop);
    let server_requests = Arc::clone(&requests);
    let server = thread::spawn(move || {
        while !server_stop.load(Ordering::Relaxed) {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("accept redirecting JSR registry request: {error}"),
            };
            stream.set_nonblocking(false).unwrap();
            let mut request = [0_u8; 4096];
            let read = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            let path = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/")
                .to_owned();
            let has_authorization = request
                .lines()
                .any(|line| line.to_ascii_lowercase().starts_with("authorization:"));
            server_requests
                .lock()
                .unwrap()
                .push((path.clone(), has_authorization));

            if path.ends_with("/1.0.0_meta.json") && path != effective_metadata_path {
                write!(
                    stream,
                    "HTTP/1.1 302 Found\r\nLocation: {effective_base_url}{effective_metadata_path}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
            } else {
                let (status, content_type, body) = match path.as_str() {
                    path if path == effective_metadata_path => {
                        ("200 OK", "application/json", metadata.as_slice())
                    }
                    path if path == effective_file_path => {
                        ("200 OK", "application/typescript", source_bytes.as_slice())
                    }
                    _ => ("404 Not Found", "text/plain", b"not found".as_slice()),
                };
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(body).unwrap();
            }
        }
    });

    (base_url, stop, requests, server)
}

pub(super) fn jsr_fetcher(
    base_url: &str,
    max_packages: usize,
) -> (tempfile::TempDir, SourceFetcher) {
    let cache = tempfile::tempdir().unwrap();
    let repositories = ArtifactRepositories::new(base_url, base_url, base_url).unwrap();
    let policy = FetchPolicy {
        offline: false,
        allowed_hosts: vec!["127.0.0.1".to_owned()],
        allow_insecure_http: true,
        repositories,
        ..FetchPolicy::default()
    };
    let limits = EngineLimits {
        max_packages,
        ..EngineLimits::default()
    };
    let fetcher = SourceFetcher::new(cache.path().join("cache"), policy, limits).unwrap();
    (cache, fetcher)
}
