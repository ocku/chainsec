use std::{
    io::{Read, Write},
    net::TcpListener,
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use base64::Engine as _;
use flate2::{Compression, write::GzEncoder};
use sha2::{Digest, Sha512};

fn npm_archive(version: &str, source: &str) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    let manifest = format!(r#"{{"name":"example","version":"{version}"}}"#);
    for (path, contents) in [
        ("package/package.json", manifest.as_str()),
        ("package/index.js", source),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, path, contents.as_bytes())
            .unwrap();
    }
    archive
        .into_inner()
        .unwrap()
        .finish()
        .expect("finish npm fixture archive")
}

fn npm_integrity(archive: &[u8]) -> String {
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(archive))
    )
}

type NpmRegistry = (
    String,
    Arc<AtomicBool>,
    Arc<Mutex<Vec<String>>>,
    thread::JoinHandle<()>,
);

fn spawn_npm_registry() -> NpmRegistry {
    let old_archive = npm_archive("1.0.0", "console.log('safe');\n");
    let intermediate_archive = npm_archive("1.5.0", "console.log('still safe');\n");
    let new_archive = npm_archive("2.0.0", "eval(payload);\n");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let base_url = format!("http://{address}");
    let metadata = serde_json::json!({
        "dist-tags": { "latest": "2.0.0" },
        "versions": {
            "1.0.0": {
                "dist": {
                    "tarball": format!("{base_url}/example-1.0.0.tgz"),
                    "integrity": npm_integrity(&old_archive),
                }
            },
            "1.5.0": {
                "dist": {
                    "tarball": format!("{base_url}/example-1.5.0.tgz"),
                    "integrity": npm_integrity(&intermediate_archive),
                }
            },
            "2.0.0": {
                "dist": {
                    "tarball": format!("{base_url}/example-2.0.0.tgz"),
                    "integrity": npm_integrity(&new_archive),
                }
            }
        }
    })
    .to_string()
    .into_bytes();
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
                Err(error) => panic!("accept registry request: {error}"),
            };
            stream.set_nonblocking(false).unwrap();
            let mut request = [0_u8; 4096];
            let read = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            let path = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/");
            server_requests.lock().unwrap().push(path.to_owned());
            let (status, content_type, body) = match path {
                "/example" => ("200 OK", "application/json", metadata.as_slice()),
                "/example-1.0.0.tgz" => {
                    ("200 OK", "application/octet-stream", old_archive.as_slice())
                }
                "/example-1.5.0.tgz" => (
                    "200 OK",
                    "application/octet-stream",
                    intermediate_archive.as_slice(),
                ),
                "/example-2.0.0.tgz" => {
                    ("200 OK", "application/octet-stream", new_archive.as_slice())
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
    });

    (base_url, stop, requests, server)
}

fn spawn_failing_npm_registry() -> NpmRegistry {
    let old_archive = npm_archive("1.0.0", "console.log('safe');\n");
    let intermediate_archive = npm_archive("1.5.0", "console.log('still safe');\n");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let base_url = format!("http://{address}");
    let metadata = serde_json::json!({
        "dist-tags": { "latest": "2.0.0" },
        "versions": {
            "1.0.0": {
                "dist": {
                    "tarball": format!("{base_url}/example-1.0.0.tgz"),
                    "integrity": npm_integrity(&old_archive),
                }
            },
            "1.5.0": {
                "dist": {
                    "tarball": format!("{base_url}/example-1.5.0.tgz"),
                    "integrity": npm_integrity(&intermediate_archive),
                }
            },
            "2.0.0": {
                "dist": {
                    "tarball": format!("{base_url}/example-2.0.0.tgz"),
                    "integrity": npm_integrity(b"expected archive"),
                }
            }
        }
    })
    .to_string()
    .into_bytes();
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
                Err(error) => panic!("accept registry request: {error}"),
            };
            stream.set_nonblocking(false).unwrap();
            let mut request = [0_u8; 4096];
            let read = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            let path = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/");
            server_requests.lock().unwrap().push(path.to_owned());
            let (status, content_type, body) = match path {
                "/example" => ("200 OK", "application/json", metadata.as_slice()),
                "/example-1.0.0.tgz" => {
                    ("200 OK", "application/octet-stream", old_archive.as_slice())
                }
                "/example-1.5.0.tgz" => (
                    "200 OK",
                    "application/octet-stream",
                    intermediate_archive.as_slice(),
                ),
                "/example-2.0.0.tgz" => (
                    "500 Internal Server Error",
                    "text/plain",
                    b"failed".as_slice(),
                ),
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
    });

    (base_url, stop, requests, server)
}

#[test]
fn json_report_has_versioned_contract() {
    let cache = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .args([
            "scan",
            "tests/fixtures/scanner",
            "--format",
            "json",
            "--max-depth",
            "0",
            "--cache",
            cache.path().to_str().unwrap(),
            "--fail-on",
            "critical",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], "1.2.0");
    assert_eq!(report["policy"]["allow_insecure_http"], false);
    assert!(report["findings"].as_array().unwrap().len() >= 3);
    let evidence = report["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|capability| capability["evidence"].as_array().unwrap())
        .next()
        .expect("fixture should produce capability evidence");
    for field in [
        "id",
        "rule_id",
        "rule_version",
        "finding_type",
        "risk",
        "confidence",
        "package",
        "file",
        "location",
        "matched_code",
        "suppressed",
    ] {
        assert!(evidence.get(field).is_some(), "missing {field}");
    }
    assert_eq!(report["statistics"]["packages"], 1);
}

#[test]
fn json_report_records_the_insecure_http_opt_in() {
    let cache = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .args([
            "scan",
            "tests/fixtures/scanner",
            "--format",
            "json",
            "--max-depth",
            "0",
            "--allow-insecure-http",
            "--cache",
            cache.path().to_str().unwrap(),
            "--fail-on",
            "critical",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["policy"]["allow_insecure_http"], true);
}

#[test]
fn human_report_is_the_default_format() {
    let cache = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .args([
            "scan",
            "tests/fixtures/scanner",
            "--max-depth",
            "0",
            "--cache",
            cache.path().to_str().unwrap(),
            "--fail-on",
            "critical",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = String::from_utf8(output.stdout).unwrap();
    assert!(report.starts_with("chainsec "));
    assert!(report.contains(" source file(s), "));
    assert!(report.contains(" source byte(s), "));
    assert!(!report.trim_start().starts_with('{'));
}

#[test]
fn human_report_filters_below_threshold_unless_verbose() {
    let cache = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .args([
            "scan",
            "tests/fixtures/scanner",
            "--max-depth",
            "0",
            "--cache",
            cache.path().to_str().unwrap(),
            "--fail-on",
            "critical",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let report = String::from_utf8(output.stdout).unwrap();
    assert!(!report.contains("High execution:chainsec.py.detection.dynamic-code-execution"));
    assert!(report.contains("Summary\n───────\nCapabilities ("));
    assert!(report.contains("Alerts (0)\n  none"));

    let verbose = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .args([
            "scan",
            "tests/fixtures/scanner",
            "--max-depth",
            "0",
            "--cache",
            cache.path().to_str().unwrap(),
            "--fail-on",
            "critical",
            "--verbose",
        ])
        .output()
        .unwrap();

    assert!(verbose.status.success());
    let report = String::from_utf8(verbose.stdout).unwrap();
    assert!(report.contains("High execution:chainsec.py.detection.dynamic-code-execution"));
}

#[test]
fn remote_diff_validates_format_and_version_history_before_network_access() {
    let cache = tempfile::tempdir().unwrap();
    let sarif = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .args([
            "remote",
            "diff",
            "npm:express",
            "--last",
            "2",
            "--format",
            "sarif",
            "--cache",
            cache.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(sarif.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&sarif.stderr);
    assert!(
        stderr.contains("support only human and JSON output"),
        "{stderr}"
    );

    let revision = "0123456789012345678901234567890123456789";
    let github = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .args([
            "remote",
            "scan",
            &format!("github:owner/repository@{revision}"),
            "--diff",
            "2",
            "--cache",
            cache.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(github.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&github.stderr)
            .contains("GitHub dependencies have no registry version history")
    );
}

#[test]
fn remote_diff_count_must_provide_a_baseline() {
    for count in ["0", "1"] {
        let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
            .args(["remote", "scan", "npm:express", "--diff", count])
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("must be at least 2"));
    }
}

fn run_registry_diff(arguments: &[&str]) -> (serde_json::Value, Vec<String>) {
    let (registry_url, stop, requests, server) = spawn_npm_registry();
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("chainsec.toml"),
        format!(
            "allow_insecure_http = true\n\n[artifactories.npm]\nmetadata_base_url = {registry_url:?}\n"
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .current_dir(project.path())
        .args(arguments)
        .args([
            "--format",
            "json",
            "--max-depth",
            "0",
            "--fail-on",
            "critical",
            "--cache",
            cache.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let requests = Arc::try_unwrap(requests).unwrap().into_inner().unwrap();
    (serde_json::from_slice(&output.stdout).unwrap(), requests)
}

fn assert_diff_versions(
    report: &serde_json::Value,
    versions: &[&str],
    comparisons: &[(&str, &str)],
) {
    assert_eq!(report["schema_version"], "1.0.0");
    assert_eq!(report["report_type"], "version_diff");
    assert_eq!(report["resolved_version"], versions[0]);
    assert_eq!(report["versions"], serde_json::json!(versions));

    let diffs = report["diffs"].as_array().unwrap();
    assert_eq!(diffs.len(), comparisons.len());
    for (diff, (from, to)) in diffs.iter().zip(comparisons) {
        assert_eq!(diff["from_version"], *from);
        assert_eq!(diff["to_version"], *to);
    }
}

fn assert_requested_archives(requests: &[String], expected: &[&str]) {
    let mut actual = requests
        .iter()
        .filter(|request| request.ends_with(".tgz"))
        .map(String::as_str)
        .collect::<Vec<_>>();
    let mut expected = expected.to_vec();
    actual.sort_unstable();
    expected.sort_unstable();
    assert_eq!(actual, expected);
}

#[test]
fn remote_scan_diff_convenience_uses_newest_and_immediate_predecessor() {
    let (report, requests) = run_registry_diff(&["remote", "scan", "npm:example", "--diff", "2"]);

    assert_diff_versions(&report, &["2.0.0", "1.5.0"], &[("1.5.0", "2.0.0")]);
    assert_requested_archives(&requests, &["/example-1.5.0.tgz", "/example-2.0.0.tgz"]);
    assert!(
        report["diffs"][0]["detections"]["added"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["rule_id"] == "chainsec.js.detection.dynamic-code-execution")
    );
    assert!(
        report["diffs"][0]["capabilities"]["added"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["name"] == "code:dynamic-execution")
    );
}

#[test]
fn remote_diff_compare_scans_only_exact_endpoints() {
    let (report, requests) = run_registry_diff(&[
        "remote",
        "diff",
        "npm:example",
        "--compare",
        "1.0.0",
        "2.0.0",
    ]);

    assert_diff_versions(&report, &["2.0.0", "1.0.0"], &[("1.0.0", "2.0.0")]);
    assert_requested_archives(&requests, &["/example-1.0.0.tgz", "/example-2.0.0.tgz"]);
}

#[test]
fn remote_diff_range_scans_inclusive_versions_and_compares_adjacent_releases() {
    let (report, requests) =
        run_registry_diff(&["remote", "diff", "npm:example", "--range", "1.0.0", "2.0.0"]);

    assert_diff_versions(
        &report,
        &["2.0.0", "1.5.0", "1.0.0"],
        &[("1.5.0", "2.0.0"), ("1.0.0", "1.5.0")],
    );
    assert_requested_archives(
        &requests,
        &[
            "/example-1.0.0.tgz",
            "/example-1.5.0.tgz",
            "/example-2.0.0.tgz",
        ],
    );
}

#[test]
fn remote_diff_stops_downloading_after_a_root_failure() {
    let (registry_url, stop, requests, server) = spawn_failing_npm_registry();
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("chainsec.toml"),
        format!(
            "allow_insecure_http = true\n\n[artifactories.npm]\nmetadata_base_url = {registry_url:?}\n"
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .current_dir(project.path())
        .args([
            "remote",
            "diff",
            "npm:example",
            "--last",
            "3",
            "--threads",
            "1",
            "--cache",
            cache.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    assert_eq!(output.status.code(), Some(2));
    let requests = Arc::try_unwrap(requests).unwrap().into_inner().unwrap();
    assert_requested_archives(&requests, &["/example-2.0.0.tgz"]);
}

#[test]
fn remote_diff_rejects_too_many_roots_before_downloading_archives() {
    let (registry_url, stop, requests, server) = spawn_npm_registry();
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("chainsec.toml"),
        format!(
            "allow_insecure_http = true\n\n[artifactories.npm]\nmetadata_base_url = {registry_url:?}\n"
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .current_dir(project.path())
        .args([
            "remote",
            "diff",
            "npm:example",
            "--range",
            "1.0.0",
            "2.0.0",
            "--max-packages",
            "2",
            "--cache",
            cache.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    assert_eq!(output.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("remote version candidates"),
        "stderr: {stderr}"
    );
    let requests = Arc::try_unwrap(requests).unwrap().into_inner().unwrap();
    assert_requested_archives(&requests, &[]);
}

#[test]
fn init_creates_a_conservative_root_config_without_scanning() {
    let project = tempfile::tempdir().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .current_dir(project.path())
        .arg("init")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.stdout.is_empty());
    let config = std::fs::read_to_string(project.path().join("chainsec.toml")).unwrap();
    assert!(project.path().join(".gitignore").exists());
    let gitignore = std::fs::read_to_string(project.path().join(".gitignore")).unwrap();
    assert!(
        gitignore
            .lines()
            .any(|line| line.trim() == ".chainsec-cache")
    );

    assert!(config.contains("max_depth = 3"));
    assert!(config.contains("# online = true"));
    assert!(config.contains("ignored_paths ="));

    let second = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .current_dir(project.path())
        .arg("init")
        .output()
        .unwrap();
    assert_eq!(second.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&second.stderr).contains("configuration already exists"));
}

#[test]
fn init_gitignore_failure_does_not_leave_config_and_can_be_retried() {
    let project = tempfile::tempdir().unwrap();
    let gitignore = project.path().join(".gitignore");
    let config = project.path().join("chainsec.toml");
    std::fs::write(&gitignore, [0xff]).unwrap();

    let failed = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .current_dir(project.path())
        .arg("init")
        .output()
        .unwrap();

    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stderr).contains("read .gitignore"));
    assert!(!config.exists());
    assert_eq!(std::fs::read(&gitignore).unwrap(), [0xff]);

    std::fs::write(&gitignore, "target/\n").unwrap();
    let retry = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .current_dir(project.path())
        .arg("init")
        .output()
        .unwrap();

    assert!(
        retry.status.success(),
        "{}",
        String::from_utf8_lossy(&retry.stderr)
    );
    assert!(config.is_file());
    assert_eq!(
        std::fs::read_to_string(gitignore).unwrap(),
        "target/\n.chainsec-cache\n"
    );
}

#[test]
fn cache_purge_removes_the_selected_cache_without_scanning() {
    let project = tempfile::tempdir().unwrap();
    let cache = project.path().join("cache");
    std::fs::create_dir_all(cache.join("npm")).unwrap();
    std::fs::write(cache.join("npm/package"), "cached").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .current_dir(project.path())
        .args(["cache", "purge", "--cache", cache.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(cache.is_dir());
    assert!(!cache.join("npm").exists());
    assert!(project.path().join("cache.locks/lifecycle.lock").is_file());
    assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 0);
    assert!(String::from_utf8_lossy(&output.stdout).contains("purged cache"));
}

#[test]
fn global_config_is_complementary_and_repository_config_takes_precedence() {
    let home = tempfile::tempdir().unwrap();
    let global_config = home.path().join(".config/chainsec");
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(&global_config).unwrap();
    std::fs::write(
        global_config.join("config.toml"),
        "format = \"human\"\nignored_rules = [\"execution:*\"]\n",
    )
    .unwrap();
    std::fs::write(project.path().join("sample.py"), "eval(payload)\n").unwrap();
    std::fs::write(
        project.path().join("chainsec.toml"),
        "format = \"json\"\nmax_depth = 0\nfail_on = \"critical\"\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .args(["--cache", cache.path().to_str().unwrap()])
        .env("HOME", home.path())
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["findings"].as_array().unwrap().is_empty());
}

#[test]
fn xdg_global_config_takes_precedence_over_home_config() {
    let xdg_config_home = tempfile::tempdir().unwrap();
    let xdg_config = xdg_config_home.path().join("chainsec");
    let home = tempfile::tempdir().unwrap();
    let home_config = home.path().join(".config/chainsec");
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(&xdg_config).unwrap();
    std::fs::create_dir_all(&home_config).unwrap();
    std::fs::write(
        xdg_config.join("config.toml"),
        "format = \"json\"\nmax_depth = 0\nfail_on = \"critical\"\n",
    )
    .unwrap();
    std::fs::write(home_config.join("config.toml"), "format = \"human\"\n").unwrap();
    std::fs::write(project.path().join("sample.py"), "print('safe')\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .args(["--cache", cache.path().to_str().unwrap()])
        .env("XDG_CONFIG_HOME", xdg_config_home.path())
        .env("HOME", home.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], "1.2.0");
}

#[test]
fn allowed_hosts_extend_across_global_project_and_cli_configuration() {
    let home = tempfile::tempdir().unwrap();
    let global_config = home.path().join(".config/chainsec");
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(&global_config).unwrap();
    std::fs::write(
        global_config.join("config.toml"),
        "online = true\nallowed_hosts = [\"global.example\", \"shared.example\"]\n",
    )
    .unwrap();
    std::fs::write(project.path().join("sample.py"), "print('safe')\n").unwrap();
    std::fs::write(
        project.path().join("chainsec.toml"),
        "max_depth = 0\nfail_on = \"critical\"\nallowed_hosts = [\"project.example\", \"shared.example\"]\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .args([
            "--format",
            "json",
            "--cache",
            cache.path().to_str().unwrap(),
            "--allow-host",
            "cli.example",
            "--allow-host",
            "shared.example",
        ])
        .env("HOME", home.path())
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["policy"]["allowed_hosts"],
        serde_json::json!([
            "global.example",
            "shared.example",
            "project.example",
            "cli.example"
        ])
    );
}

#[test]
fn generic_repository_credentials_use_configured_environment_variables() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("sample.py"), "print('safe')\n").unwrap();
    std::fs::write(
        project.path().join("chainsec.toml"),
        r#"
[artifactories.npm]
metadata_base_url = "https://packages.example/npm"

[artifactories.npm.credential]
scope = "https://packages.example/private/"
bearer_token_env = "CHAINSEC_TEST_REGISTRY_TOKEN"
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .args([
            "--online",
            "--max-depth",
            "0",
            "--cache",
            cache.path().to_str().unwrap(),
            "--fail-on",
            "critical",
        ])
        .env("CHAINSEC_TEST_REGISTRY_TOKEN", "test-token")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn custom_rule_pack_is_loaded_end_to_end() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let pack = tempfile::NamedTempFile::with_suffix(".json").unwrap();
    std::fs::write(project.path().join("sample.py"), "danger(payload)\n").unwrap();
    std::fs::write(
        pack.path(),
        r#"{"rules":[{"id":"CUSTOM001","version":1,"language":"python","finding_type":"arbitrary_code_execution","risk":"high","confidence":"high","rationale":"Custom dangerous call.","remediation":"Remove it.","query":"(call function: (identifier) @callee (#eq? @callee \"danger\")) @match"}]}"#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .args([
            "--format",
            "json",
            "--max-depth",
            "0",
            "--cache",
            cache.path().to_str().unwrap(),
            "--no-default-rules",
            "--rule-pack",
            pack.path().to_str().unwrap(),
            "--fail-on",
            "critical",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["findings"][0]["rule_id"], "CUSTOM001");
}

#[test]
fn ignored_rule_is_absent_from_the_report() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("sample.py"), "eval(payload)\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .args([
            "--format",
            "json",
            "--max-depth",
            "0",
            "--cache",
            cache.path().to_str().unwrap(),
            "--ignore-rule",
            "chainsec.py.detection.dynamic-code-execution",
            "--fail-on",
            "high",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["rule_id"] != "chainsec.py.detection.dynamic-code-execution")
    );
}

#[test]
fn ignore_rule_supports_grouped_globs() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("sample.py"),
        "import requests\nopen('output.txt', 'w')\nrequests.get('https://example.test')\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .args([
            "--format",
            "json",
            "--max-depth",
            "0",
            "--cache",
            cache.path().to_str().unwrap(),
            "--ignore-rule",
            "network:*",
            "--ignore-rule",
            "filesystem:*",
            "--fail-on",
            "critical",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| {
                finding["finding_type"] != "network_access"
                    && finding["finding_type"] != "filesystem_access"
            })
    );
}

#[test]
fn configured_suppression_is_auditable_and_does_not_fail_the_scan() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("sample.py"), "eval(payload)\n").unwrap();
    std::fs::write(
        project.path().join("chainsec.toml"),
        r#"
max_depth = 0
fail_on = "high"

[[suppressions]]
rule = "execution:chainsec.py.detection.dynamic-code-execution"
package = "root"
reason = "The expression is an approved, constrained evaluator."
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .args([
            "--format",
            "json",
            "--cache",
            cache.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let finding = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["rule_id"] == "chainsec.py.detection.dynamic-code-execution")
        .unwrap();
    assert_eq!(finding["suppressed"], true);
    assert_eq!(
        finding["suppression"]["reason"],
        "The expression is an approved, constrained evaluator."
    );
}

#[test]
fn human_report_includes_rule_group_and_dependency() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("sample.py"), "open('/etc/passwd')\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .args([
            "--max-depth",
            "0",
            "--cache",
            cache.path().to_str().unwrap(),
            "--format",
            "human",
            "--fail-on",
            "critical",
            "--verbose",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("filesystem:chainsec.py.detection.filesystem-open"));
    assert!(stdout.contains("[root]"));
}

#[test]
fn root_config_ignores_rules_and_paths() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::create_dir(project.path().join("tests")).unwrap();
    std::fs::write(project.path().join("sample.py"), "eval(payload)\n").unwrap();
    std::fs::write(
        project.path().join("tests/ignored.py"),
        "open('secret', 'w')\n",
    )
    .unwrap();
    std::fs::write(
        project.path().join("chainsec.toml"),
        "max_depth = 0\nignored_rules = [\"execution:chainsec.py.detection.dynamic-code-execution\"]\nignored_paths = [\"tests/*\"]\nfail_on = \"high\"\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .args([
            "--format",
            "json",
            "--cache",
            cache.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["findings"].as_array().unwrap().is_empty());
}

#[test]
fn cli_ignores_root_paths() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::create_dir(project.path().join("generated")).unwrap();
    std::fs::write(
        project.path().join("generated/ignored.py"),
        "open('secret', 'w')\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .args([
            "--format",
            "json",
            "--max-depth",
            "0",
            "--cache",
            cache.path().to_str().unwrap(),
            "--ignore-path",
            "generated/**",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["findings"].as_array().unwrap().is_empty());
}

#[test]
fn root_config_ignores_packages_before_fetching() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("package.json"),
        r#"{"dependencies":{"example":"1.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        project.path().join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{"dependencies":{"example":"1.0.0"}},"node_modules/example":{"version":"1.0.0","resolved":"https://registry.npmjs.org/example/-/example-1.0.0.tgz","integrity":"sha512-ignored"}}}"#,
    )
    .unwrap();
    std::fs::write(
        project.path().join("chainsec.toml"),
        "ignored_packages = [\"npm:example@1.0.0\"]\nfail_on = \"critical\"\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .args([
            "--format",
            "json",
            "--cache",
            cache.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["statistics"]["packages"], 1);
    assert!(report["issues"].as_array().unwrap().is_empty());
}

#[test]
fn install_script_priorities_distinguish_npm_and_python() {
    let npm = tempfile::tempdir().unwrap();
    let npm_cache = tempfile::tempdir().unwrap();
    std::fs::write(
        npm.path().join("package.json"),
        r#"{"name":"fixture","scripts":{"install":"node setup.js"}}"#,
    )
    .unwrap();
    let npm_output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(npm.path())
        .args([
            "--format",
            "json",
            "--allow-unlocked",
            "--cache",
            npm_cache.path().to_str().unwrap(),
            "--fail-on",
            "high",
        ])
        .output()
        .unwrap();
    assert_eq!(npm_output.status.code(), Some(1));
    let npm_report: serde_json::Value = serde_json::from_slice(&npm_output.stdout).unwrap();
    assert_eq!(
        npm_report["findings"][0]["rule_id"],
        "chainsec.js.detection.manifest.install-hook"
    );
    assert_eq!(npm_report["findings"][0]["risk"], "high");

    let python = tempfile::tempdir().unwrap();
    let python_cache = tempfile::tempdir().unwrap();
    std::fs::write(python.path().join("setup.py"), "print('install')\n").unwrap();
    let python_output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(python.path())
        .args([
            "--format",
            "json",
            "--allow-unlocked",
            "--cache",
            python_cache.path().to_str().unwrap(),
            "--fail-on",
            "high",
        ])
        .output()
        .unwrap();
    assert!(
        python_output.status.success(),
        "{}",
        String::from_utf8_lossy(&python_output.stderr)
    );
    let python_report: serde_json::Value = serde_json::from_slice(&python_output.stdout).unwrap();
    assert_eq!(
        python_report["findings"][0]["rule_id"],
        "chainsec.py.detection.manifest.install-hook"
    );
    assert_eq!(python_report["findings"][0]["risk"], "medium");
}

#[test]
fn unsupported_artifact_scheme_uses_policy_exit_code() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("package.json"),
        r#"{"dependencies":{"example":"1.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        project.path().join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{"dependencies":{"example":"1.0.0"}},"node_modules/example":{"version":"1.0.0","resolved":"ftp://packages.example.test/example.tgz","integrity":"sha512-ignored"}}}"#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .args([
            "--format",
            "json",
            "--online",
            "--allow-host",
            "packages.example.test",
            "--cache",
            cache.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue["code"] == "policy_error")
    );
}

#[test]
fn offline_flag_is_not_available() {
    let project = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .arg("--offline")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected argument '--offline'"));
}

#[test]
fn human_formatted_size_limits_are_accepted() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .args([
            "--max-depth",
            "0",
            "--max-archive",
            "100m",
            "--max-extracted",
            "100M",
            "--max-source-file",
            "100MiB",
            "--cache",
            cache.path().to_str().unwrap(),
            "--fail-on",
            "critical",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn online_without_allowlist_allows_local_only_scans() {
    let project = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .args(["--online", "--max-depth", "0"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn output_file_contains_analysis_and_leaves_stdout_empty() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let report_file = tempfile::NamedTempFile::new().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .args([
            "--format",
            "json",
            "--max-depth",
            "0",
            "--cache",
            cache.path().to_str().unwrap(),
            "--output",
            report_file.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(report_file.path()).unwrap()).unwrap();
    assert_eq!(report["schema_version"], "1.2.0");
}

#[test]
fn unlocked_dependency_uses_policy_exit_code() {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("package.json"),
        r#"{"dependencies":{"example":"^1"}}"#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chainsec"))
        .arg("scan")
        .arg(project.path())
        .args([
            "--format",
            "json",
            "--cache",
            cache.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue["code"] == "policy_error")
    );
}
