use std::{
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    sync::Arc,
    thread,
    time::Duration,
};

use reqwest::redirect::Policy;
use rustls::{ServerConfig, ServerConnection, StreamOwned, pki_types::PrivateKeyDer};
use url::Url;

use crate::{
    fetcher::{ArtifactRepositories, FetchPolicy, SourceFetcher},
    model::{Dependency, Ecosystem, EngineLimits},
};

use super::{artifact_url_is_lockfile_defined, diagnostic_url, jsr_package_name};

#[test]
fn diagnostic_urls_redact_queries_and_fragments() {
    let url = Url::parse(
        "https://artifacts.example/private/package.tgz?token=secret&signature=value#fragment",
    )
    .unwrap();

    let diagnostic = diagnostic_url(&url);

    assert_eq!(diagnostic, "https://artifacts.example/private/package.tgz");
    assert!(!diagnostic.contains("secret"));
    assert!(!diagnostic.contains("signature"));
}

#[test]
fn diagnostic_urls_redact_path_embedded_credentials() {
    let token = "a".repeat(64);
    let github_token = "ghp_".to_owned() + &"b".repeat(36);
    let url = Url::parse(&format!(
        "https://user:password@artifacts.example/artifactory/api/npm/{token}/package.tgz"
    ))
    .unwrap();
    let github_url = Url::parse(&format!(
        "https://github.example/artifactory/{github_token}/package.tgz?query=ignored"
    ))
    .unwrap();

    let diagnostic = diagnostic_url(&url);
    let github_diagnostic = diagnostic_url(&github_url);

    assert_eq!(
        diagnostic,
        "https://artifacts.example/artifactory/api/npm/[redacted]/package.tgz"
    );
    assert!(!diagnostic.contains(&token));
    assert!(!diagnostic.contains("user"));
    assert!(!diagnostic.contains("password"));

    assert_eq!(
        github_diagnostic,
        "https://github.example/artifactory/[redacted]/package.tgz"
    );
    assert!(!github_diagnostic.contains(&github_token));
}

#[test]
fn preserves_the_scope_when_parsing_an_unversioned_jsr_package() {
    assert_eq!(jsr_package_name("jsr:@std/fs"), "@std/fs");
    assert_eq!(jsr_package_name("jsr:@std/fs@1.0.0"), "@std/fs");
}

#[test]
fn lockfile_artifact_urls_never_receive_repository_credentials() {
    let locked_npm = Dependency {
        ecosystem: Ecosystem::Npm,
        name: "example".to_owned(),
        requirement: "1.0.0".to_owned(),
        resolved_version: Some("1.0.0".to_owned()),
        source_url: Some("https://packages.example/npm/example-1.0.0.tgz".to_owned()),
        integrity: Some("sha512-placeholder".to_owned()),
        lockfile: Some(PathBuf::from("package-lock.json")),
        deno_lockfile_snapshot: None,
        registry_integrity_required: false,
    };
    assert!(artifact_url_is_lockfile_defined(&locked_npm));

    let mut resolved_from_repository = locked_npm.clone();
    resolved_from_repository.lockfile = None;
    assert!(!artifact_url_is_lockfile_defined(&resolved_from_repository));
}

#[tokio::test]
async fn scopes_credentials_and_rejects_https_downgrades_to_unrelated_loopback() {
    let tls = LocalTlsFixture::new();
    let (in_scope_url, in_scope_requests) = tls.serve(vec![
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
    ]);
    let repositories = ArtifactRepositories::default()
        .with_npm_metadata_base_url(&in_scope_url)
        .unwrap()
        .with_bearer_token(format!("{in_scope_url}/private/"), "secret")
        .unwrap();
    let fetcher = fetcher_with_tls_certificate(&tls, repositories, false);

    assert_eq!(
        fetcher
            .download(
                &Url::parse(&format!("{in_scope_url}/private/package")).unwrap(),
                true
            )
            .await
            .unwrap(),
        b"ok"
    );
    assert!(has_bearer_token(
        in_scope_requests.join().unwrap().first().unwrap()
    ));

    let (out_of_scope_url, out_of_scope_requests) = tls.serve(vec![
        b"HTTP/1.1 302 Found\r\nLocation: /public/package\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
    ]);
    let repositories = ArtifactRepositories::default()
        .with_npm_metadata_base_url(&out_of_scope_url)
        .unwrap()
        .with_bearer_token(format!("{out_of_scope_url}/private/"), "secret")
        .unwrap();
    let fetcher = fetcher_with_tls_certificate(&tls, repositories, false);

    assert_eq!(
        fetcher
            .download(
                &Url::parse(&format!("{out_of_scope_url}/private/package")).unwrap(),
                true,
            )
            .await
            .unwrap(),
        b"ok"
    );
    let requests = out_of_scope_requests.join().unwrap();
    assert!(has_bearer_token(&requests[0]));
    assert!(!has_bearer_token(&requests[1]));

    let (http_url, http_requests) = serve_http(Vec::new());
    let (downgrade_url, downgrade_requests) = tls.serve(vec![
        format!("HTTP/1.1 302 Found\r\nLocation: {http_url}/package\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes(),
    ]);
    let repositories = ArtifactRepositories::default()
        .with_npm_metadata_base_url(&downgrade_url)
        .unwrap()
        .with_bearer_token(format!("{downgrade_url}/private/"), "secret")
        .unwrap();
    let fetcher = fetcher_with_tls_certificate(&tls, repositories, true);

    let error = fetcher
        .download(
            &Url::parse(&format!("{downgrade_url}/private/package")).unwrap(),
            true,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("network redirect"));
    assert!(error.to_string().contains("insecure URL"));
    assert!(has_bearer_token(
        downgrade_requests.join().unwrap().first().unwrap()
    ));
    assert!(http_requests.join().unwrap().is_empty());
}

#[tokio::test]
async fn metadata_derived_artifacts_cannot_select_another_repository_credential() {
    let tls = LocalTlsFixture::new();
    let (artifact_url, artifact_requests) = tls.serve(vec![
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
    ]);
    let metadata_base = Url::parse("https://localhost:1/npm").unwrap();
    let repositories = ArtifactRepositories::default()
        .with_npm_metadata_base_url(metadata_base.as_str())
        .unwrap()
        .with_bearer_token(format!("{artifact_url}/private/"), "secret")
        .unwrap();
    let fetcher = fetcher_with_tls_certificate(&tls, repositories, false);
    let mut budget = fetcher.network_budget();

    assert_eq!(
        fetcher
            .download_with_budget_from_repository(
                &Url::parse(&format!("{artifact_url}/private/example.tgz")).unwrap(),
                &metadata_base,
                &mut budget,
            )
            .await
            .unwrap(),
        b"ok"
    );
    assert!(!has_bearer_token(
        artifact_requests.join().unwrap().first().unwrap()
    ));
}

#[tokio::test]
async fn rejects_plaintext_direct_urls_even_with_the_loopback_repository_opt_in() {
    let cache = tempfile::tempdir().unwrap();
    let fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        FetchPolicy {
            offline: false,
            allowed_hosts: vec!["127.0.0.1".to_owned()],
            allow_insecure_http: true,
            ..FetchPolicy::default()
        },
        EngineLimits::default(),
    )
    .unwrap();

    let error = fetcher
        .download(&Url::parse("http://127.0.0.1:1/private").unwrap(), false)
        .await
        .unwrap_err();

    assert!(matches!(error, crate::Error::Policy { .. }));
    assert!(
        error
            .to_string()
            .contains("plaintext HTTP is permitted only")
    );
}

#[tokio::test]
async fn rejects_http_repository_redirects_outside_loopback_with_the_opt_in() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 1024];
        let _read = stream.read(&mut request).unwrap();
        stream
            .write_all(b"HTTP/1.1 302 Found\r\nLocation: http://example.test/archive\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
    });
    let cache = tempfile::tempdir().unwrap();
    let repository_base = format!("{base_url}/private");
    let repositories =
        ArtifactRepositories::new(&repository_base, &repository_base, &repository_base).unwrap();
    let fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        FetchPolicy {
            offline: false,
            allowed_hosts: vec!["127.0.0.1".to_owned(), "example.test".to_owned()],
            repositories,
            allow_insecure_http: true,
            ..FetchPolicy::default()
        },
        EngineLimits::default(),
    )
    .unwrap();

    let error = fetcher
        .download(
            &Url::parse(&format!("{repository_base}/package")).unwrap(),
            true,
        )
        .await
        .err()
        .unwrap();
    server.join().unwrap();
    assert!(error.to_string().contains("network redirect"));
    assert!(error.to_string().contains("insecure URL"));
}

#[tokio::test]
async fn rejects_registry_provided_artifact_hosts_outside_the_allowlist() {
    let cache = tempfile::tempdir().unwrap();
    let fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        FetchPolicy {
            offline: false,
            allowed_hosts: vec!["metadata.example.test".to_owned()],
            repositories: ArtifactRepositories::default()
                .with_pypi_metadata_base_url("https://metadata.example.test/pypi")
                .unwrap()
                .with_pypi_artifact_base_url("https://artifacts.example.test/packages")
                .unwrap(),
            ..FetchPolicy::default()
        },
        EngineLimits::default(),
    )
    .unwrap();

    let error = fetcher
        .download(
            &Url::parse("https://untrusted-artifacts.example.test/example.tar.gz").unwrap(),
            true,
        )
        .await
        .unwrap_err();

    assert!(error.to_string().contains("not in the allowlist"));
}

struct LocalTlsFixture {
    server_config: Arc<ServerConfig>,
    root_certificate: reqwest::Certificate,
}

impl LocalTlsFixture {
    fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let parameters = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        let certificate = parameters.self_signed(&key_pair).unwrap();
        let root_certificate = reqwest::Certificate::from_der(certificate.der()).unwrap();
        let private_key = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.der().clone()], private_key)
            .unwrap();
        Self {
            server_config: Arc::new(server_config),
            root_certificate,
        }
    }

    fn serve(&self, responses: Vec<Vec<u8>>) -> (String, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        );
        let server_config = Arc::clone(&self.server_config);
        let server = thread::spawn(move || {
            responses
                .into_iter()
                .map(|response| {
                    let (stream, _) = listener.accept().unwrap();
                    let connection = ServerConnection::new(Arc::clone(&server_config)).unwrap();
                    let mut stream = StreamOwned::new(connection, stream);
                    let request = read_request(&mut stream);
                    stream.write_all(&response).unwrap();
                    request
                })
                .collect()
        });
        (url, server)
    }
}

fn fetcher_with_tls_certificate(
    tls: &LocalTlsFixture,
    repositories: ArtifactRepositories,
    allow_insecure_http: bool,
) -> SourceFetcher {
    let cache = tempfile::tempdir().unwrap();
    let mut fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        FetchPolicy {
            offline: false,
            allowed_hosts: vec!["localhost".to_owned(), "127.0.0.1".to_owned()],
            repositories,
            allow_insecure_http,
            ..FetchPolicy::default()
        },
        EngineLimits::default(),
    )
    .unwrap();
    fetcher.client = Some(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .no_proxy()
            .redirect(Policy::none())
            .add_root_certificate(tls.root_certificate.clone())
            .build()
            .unwrap(),
    );
    fetcher
}

fn serve_http(responses: Vec<Vec<u8>>) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let server = thread::spawn(move || {
        responses
            .into_iter()
            .map(|response| {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_request(&mut stream);
                stream.write_all(&response).unwrap();
                request
            })
            .collect()
    });
    (url, server)
}

fn read_request(stream: &mut impl Read) -> String {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buffer).unwrap();
        assert_ne!(
            read, 0,
            "connection closed before sending a complete request"
        );
        request.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8(request).unwrap()
}

fn has_bearer_token(request: &str) -> bool {
    request
        .lines()
        .any(|header| header.eq_ignore_ascii_case("authorization: bearer secret"))
}
