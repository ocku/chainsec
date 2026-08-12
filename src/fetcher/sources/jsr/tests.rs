use super::*;
use crate::{
    fetcher::{ArtifactRepositories, FetchPolicy},
    model::Ecosystem,
};
use std::{
    collections::HashSet,
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

type JsrRegistry = (
    String,
    Arc<AtomicBool>,
    Arc<Mutex<Vec<String>>>,
    thread::JoinHandle<()>,
);

type RedirectingJsrRegistry = (
    String,
    Arc<AtomicBool>,
    Arc<Mutex<Vec<(String, bool)>>>,
    thread::JoinHandle<()>,
);

#[cfg(unix)]
#[test]
fn cached_jsr_fifo_is_rejected_without_blocking() {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};

    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("cached");
    fs::create_dir(&source).unwrap();
    let relative = Path::new("nested/module.ts");
    fs::create_dir(source.join("nested")).unwrap();
    let fifo = source.join(relative);
    let fifo = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: the CString is a valid, NUL-terminated filesystem path.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

    let root = TrustedDir::open(&source).unwrap();
    assert!(matches!(
        read_cached_jsr_file(&root, &source, relative, 1024),
        Err(Error::Policy { operation, .. }) if operation == "cache validation"
    ));
}

fn spawn_jsr_registry(
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
            server_requests.lock().unwrap().push(path.clone());
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

fn spawn_jsr_package_registry(
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
            server_requests.lock().unwrap().push(path.clone());
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

fn spawn_redirecting_jsr_registry(source_bytes: &[u8]) -> RedirectingJsrRegistry {
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

fn jsr_fetcher(base_url: &str, max_packages: usize) -> (tempfile::TempDir, SourceFetcher) {
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

#[tokio::test]
async fn jsr_rejects_insecure_redirects_outside_the_configured_repository_scope() {
    let source_bytes = b"export const redirected = true;\n";
    let (base_url, stop, requests, server) = spawn_redirecting_jsr_registry(source_bytes);
    let repository_url = format!("{base_url}/registry");
    let cache = tempfile::tempdir().unwrap();
    let repositories = ArtifactRepositories::new(&repository_url, &repository_url, &repository_url)
        .unwrap()
        .with_bearer_token(&repository_url, "origin-secret")
        .unwrap();
    let policy = FetchPolicy {
        offline: false,
        allowed_hosts: vec!["127.0.0.1".to_owned(), "localhost".to_owned()],
        allow_insecure_http: true,
        repositories,
        ..FetchPolicy::default()
    };
    let fetcher =
        SourceFetcher::new(cache.path().join("cache"), policy, EngineLimits::default()).unwrap();
    let mut dependency = Dependency::declared(
        Ecosystem::Deno,
        "@scope/package",
        "jsr:@scope/package@1.0.0",
    );

    let error = fetcher
        .pin_jsr_version(&mut dependency, "@scope/package", "1.0.0".to_owned())
        .await
        .unwrap_err();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    assert!(error.to_string().contains("network redirect"));
    assert!(error.to_string().contains("insecure URL"));
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].0.starts_with("/registry/"));
    assert!(!requests[0].1);
    assert!(!requests.iter().any(|(path, _)| path.starts_with("/cdn/")));
}

#[tokio::test]
async fn jsr_file_loop_enforces_a_per_acquisition_request_limit() {
    let files = [
        ("first.ts", b"first".as_slice()),
        ("second.ts", b"second".as_slice()),
    ];
    let ((base_url, stop, requests, server), integrity) =
        spawn_jsr_package_registry(&files, Duration::ZERO);
    let (_cache, mut fetcher) = jsr_fetcher(&base_url, 10);
    fetcher.limits.max_network_requests = 2;
    let metadata_url = fetcher
        .policy
        .repositories
        .jsr_version_metadata_url("@scope/package", "1.0.0")
        .unwrap();
    let temporary = tempfile::tempdir().unwrap();

    let error = fetcher
        .fetch_jsr_package(&metadata_url, temporary.path(), Some(&integrity))
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
async fn jsr_file_loop_enforces_an_end_to_end_acquisition_deadline() {
    let files = [
        ("first.ts", b"first".as_slice()),
        ("second.ts", b"second".as_slice()),
    ];
    let ((base_url, stop, requests, server), integrity) =
        spawn_jsr_package_registry(&files, Duration::from_millis(40));
    let (_cache, mut fetcher) = jsr_fetcher(&base_url, 10);
    fetcher.limits.max_acquisition_duration = Duration::from_millis(70);
    let metadata_url = fetcher
        .policy
        .repositories
        .jsr_version_metadata_url("@scope/package", "1.0.0")
        .unwrap();
    let temporary = tempfile::tempdir().unwrap();

    let error = fetcher
        .fetch_jsr_package(&metadata_url, temporary.path(), Some(&integrity))
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

#[test]
fn selects_highest_non_yanked_jsr_release_matching_requirement() {
    let dependency = Dependency::declared(Ecosystem::Deno, "assert", "jsr:@std/assert@^1.0.0");
    let metadata = serde_json::json!({
        "versions": {
            "1.0.0": {},
            "1.2.0": {},
            "1.3.0": { "yanked": true },
            "2.0.0": {}
        }
    });

    assert_eq!(
        select_jsr_version(&dependency, "^1.0.0", &metadata).unwrap(),
        "1.2.0"
    );
}

#[test]
fn parses_unversioned_scoped_jsr_package() {
    let dependency = Dependency::declared(Ecosystem::Deno, "assert", "jsr:@std/assert");

    assert_eq!(
        jsr_package_and_requirement(&dependency).unwrap(),
        ("@std/assert", "*")
    );
}

#[tokio::test]
async fn last_selection_skips_an_unavailable_newest_jsr_version() {
    let (base_url, stop, requests, server) = spawn_jsr_registry(
        serde_json::json!({
            "versions": {"3.0.0": {}, "2.0.0": {}, "1.0.0": {}}
        }),
        &["3.0.0"],
        &[],
    );
    let (_cache, fetcher) = jsr_fetcher(&base_url, 3);
    let dependency = Dependency::declared(Ecosystem::Deno, "@std/assert", "jsr:@std/assert");

    let versions = fetcher
        .resolve_jsr_version_selection(dependency, RemoteVersionSelection::Last(2))
        .await
        .unwrap();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    assert_eq!(
        versions
            .iter()
            .map(|dependency| dependency.resolved_version.as_deref().unwrap())
            .collect::<Vec<_>>(),
        ["2.0.0", "1.0.0"]
    );
    assert_eq!(
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|path| path.ends_with("_meta.json"))
            .count(),
        3
    );
}

#[tokio::test]
async fn last_selection_fails_on_malformed_successful_version_metadata() {
    let (base_url, stop, requests, server) = spawn_jsr_registry(
        serde_json::json!({
            "versions": {"3.0.0": {}, "2.0.0": {}, "1.0.0": {}}
        }),
        &[],
        &["3.0.0"],
    );
    let (_cache, fetcher) = jsr_fetcher(&base_url, 3);
    let dependency = Dependency::declared(Ecosystem::Deno, "@std/assert", "jsr:@std/assert");

    let error = fetcher
        .resolve_jsr_version_selection(dependency, RemoteVersionSelection::Last(2))
        .await
        .unwrap_err();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    assert!(error.to_string().contains("invalid JSR version metadata"));
    assert_eq!(
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|path| path.ends_with("_meta.json"))
            .count(),
        1
    );
}

#[tokio::test]
async fn range_selection_fails_on_malformed_historical_version_metadata() {
    let (base_url, stop, requests, server) = spawn_jsr_registry(
        serde_json::json!({
            "versions": {"3.0.0": {}, "2.0.0": {}, "1.0.0": {}}
        }),
        &[],
        &["2.0.0"],
    );
    let (_cache, fetcher) = jsr_fetcher(&base_url, 3);
    let dependency = Dependency::declared(Ecosystem::Deno, "@std/assert", "jsr:@std/assert");

    let error = fetcher
        .resolve_jsr_version_selection(
            dependency,
            RemoteVersionSelection::Range {
                from: "1.0.0".to_owned(),
                to: "3.0.0".to_owned(),
            },
        )
        .await
        .unwrap_err();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    assert!(error.to_string().contains("invalid JSR version metadata"));
    assert_eq!(
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|path| path.ends_with("_meta.json"))
            .count(),
        2
    );
}

#[tokio::test]
async fn jsr_selection_stops_after_exceeding_the_root_limit() {
    let (base_url, stop, requests, server) = spawn_jsr_registry(
        serde_json::json!({
            "versions": {"3.0.0": {}, "2.0.0": {}, "1.0.0": {}}
        }),
        &[],
        &[],
    );
    let (_cache, fetcher) = jsr_fetcher(&base_url, 1);
    let dependency = Dependency::declared(Ecosystem::Deno, "@std/assert", "jsr:@std/assert");

    let error = fetcher
        .resolve_jsr_version_selection(dependency, RemoteVersionSelection::Last(3))
        .await
        .unwrap_err();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    assert_eq!(error.code(), "limit_exceeded");
    assert!(error.to_string().contains("remote version candidates"));
    assert_eq!(
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|path| path.ends_with("_meta.json"))
            .count(),
        1
    );
}

#[test]
fn orders_selected_and_older_non_yanked_jsr_versions_semantically() {
    let dependency = Dependency::declared(Ecosystem::Deno, "assert", "jsr:@std/assert@latest");
    let metadata = serde_json::json!({
        "versions": {
            "10.0.0": {},
            "2.0.0": {},
            "1.10.0": { "yanked": true },
            "1.9.0": {},
            "1.2.0": {}
        }
    });

    assert_eq!(
        jsr_versions_at_or_below(&dependency, "2.0.0", &metadata).unwrap(),
        ["2.0.0", "1.9.0", "1.2.0"]
    );
}

#[test]
fn compares_exact_non_yanked_jsr_endpoints_in_to_from_order() {
    let dependency = Dependency::declared(Ecosystem::Deno, "assert", "jsr:@std/assert");
    let metadata = serde_json::json!({
        "versions": {
            "1.0.0": {},
            "1.5.0": {},
            "2.0.0": {}
        }
    });

    assert_eq!(
        jsr_compare_versions(&dependency, "1.0.0", "2.0.0", &metadata).unwrap(),
        ["2.0.0", "1.0.0"]
    );
}

#[test]
fn ranges_include_endpoints_and_exclude_yanked_jsr_intermediates() {
    let dependency = Dependency::declared(Ecosystem::Deno, "assert", "jsr:@std/assert");
    let metadata = serde_json::json!({
        "versions": {
            "0.9.0": {},
            "1.0.0": {},
            "1.4.0": { "yanked": true },
            "1.6.0": {},
            "2.0.0": {},
            "3.0.0": {}
        }
    });

    assert_eq!(
        jsr_range_versions(&dependency, "1.0.0", "2.0.0", &metadata).unwrap(),
        ["2.0.0", "1.6.0", "1.0.0"]
    );
}

#[test]
fn rejects_yanked_equal_and_reversed_jsr_endpoints() {
    let dependency = Dependency::declared(Ecosystem::Deno, "assert", "jsr:@std/assert");
    let metadata = serde_json::json!({
        "versions": {
            "1.0.0": {},
            "1.5.0": { "yanked": true },
            "2.0.0": {}
        }
    });

    assert!(
        jsr_compare_versions(&dependency, "1.5.0", "2.0.0", &metadata)
            .unwrap_err()
            .to_string()
            .contains("yanked")
    );
    assert!(
        jsr_compare_versions(&dependency, "invalid", "2.0.0", &metadata)
            .unwrap_err()
            .to_string()
            .contains("semantic version")
    );
    assert!(
        jsr_compare_versions(&dependency, "1.0.0", "1.0.0", &metadata)
            .unwrap_err()
            .to_string()
            .contains("distinct")
    );
    assert!(
        jsr_range_versions(&dependency, "2.0.0", "1.0.0", &metadata)
            .unwrap_err()
            .to_string()
            .contains("must be older")
    );
}

#[test]
fn cached_jsr_files_are_rebuilt_only_when_bound_to_the_verified_manifest() {
    let cache = tempfile::tempdir().unwrap();
    let fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        FetchPolicy::default(),
        EngineLimits::default(),
    )
    .unwrap();
    let metadata_url = Url::parse("https://jsr.io/@scope/package/1.0.0_meta.json").unwrap();
    let source_bytes = b"export const safe = true;\n";
    let checksum = format!("sha256-{}", hex::encode(Sha256::digest(source_bytes)));
    let metadata_bytes = serde_json::to_vec(&serde_json::json!({
        "manifest": {
            "/mod.ts": {
                "size": source_bytes.len(),
                "checksum": checksum,
            }
        }
    }))
    .unwrap();
    let metadata_integrity = format!("sha256:{}", hex::encode(Sha256::digest(&metadata_bytes)));
    let cached_source = cache.path().join("cached");
    fs::create_dir(&cached_source).unwrap();
    fs::write(cached_source.join("mod.ts"), source_bytes).unwrap();

    let temporary = cache.path().join("temporary");
    fs::create_dir(&temporary).unwrap();
    let (source, _, stats) = fetcher
        .rebuild_cached_jsr_package(
            &metadata_url,
            &temporary,
            Some(&metadata_integrity),
            &metadata_bytes,
            &cached_source,
        )
        .unwrap();
    assert_eq!(stats.files, 1);
    assert_eq!(fs::read(source.join("mod.ts")).unwrap(), source_bytes);

    fs::write(
        cached_source.join("mod.ts"),
        b"export const safe = false;\n",
    )
    .unwrap();
    let tampered_temporary = cache.path().join("tampered-temporary");
    fs::create_dir(&tampered_temporary).unwrap();
    let error = fetcher
        .rebuild_cached_jsr_package(
            &metadata_url,
            &tampered_temporary,
            Some(&metadata_integrity),
            &metadata_bytes,
            &cached_source,
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("size mismatch")
            || error.to_string().contains("checksum verification failed")
    );
}
