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

pub(super) type NpmRegistry = (
    String,
    Arc<AtomicBool>,
    Arc<Mutex<Vec<String>>>,
    thread::JoinHandle<()>,
);

pub(super) fn spawn_npm_registry() -> NpmRegistry {
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

pub(super) fn spawn_failing_npm_registry() -> NpmRegistry {
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
