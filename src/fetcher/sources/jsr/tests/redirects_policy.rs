use super::{support::*, *};

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
