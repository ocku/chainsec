use std::{io::Read, path::PathBuf, str::FromStr};

use node_semver::{Range as NpmRange, Version as NpmVersion};
use pep440_rs::{Version, VersionSpecifiers};
use serde_json::Value as JsonValue;
use url::Url;

use crate::{
    error::{Error, Result},
    model::{Dependency, Ecosystem},
};

use super::{SafeSourceFetcher, host_is_allowed};

impl SafeSourceFetcher {
    pub(super) fn resolve_unlocked_python(&self, dependency: &mut Dependency) -> Result<()> {
        let api = Url::parse(&format!("https://pypi.org/pypi/{}/json", dependency.name))
            .expect("static PyPI URL is valid");
        let metadata: JsonValue =
            serde_json::from_slice(&self.download(&api)?).map_err(|error| Error::Resolution {
                package: dependency.id(),
                message: format!("invalid PyPI response: {error}"),
            })?;
        resolve_python_release(dependency, &metadata)
    }

    pub(super) fn resolve_unlocked_npm(&self, dependency: &mut Dependency) -> Result<()> {
        let (package, requirement) = npm_package_and_requirement(dependency);
        let encoded = url::form_urlencoded::byte_serialize(package.as_bytes()).collect::<String>();
        let api = Url::parse(&format!("https://registry.npmjs.org/{encoded}"))
            .expect("encoded npm registry URL is valid");
        let metadata: JsonValue =
            serde_json::from_slice(&self.download(&api)?).map_err(|error| Error::Resolution {
                package: dependency.id(),
                message: format!("invalid npm registry response: {error}"),
            })?;
        resolve_npm_release(dependency, requirement, &metadata)
    }

    fn check_url(&self, url: &Url) -> Result<()> {
        if self.policy.offline {
            return Err(Error::Policy {
                operation: "network fetch".to_owned(),
                message: "offline mode is enabled".to_owned(),
            });
        }
        if !matches!(url.scheme(), "http" | "https") {
            return Err(Error::Policy {
                operation: "network fetch".to_owned(),
                message: format!(
                    "scheme {} is forbidden; only http and https are allowed",
                    url.scheme()
                ),
            });
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(Error::Policy {
                operation: "network fetch".to_owned(),
                message: "URL credentials are forbidden".to_owned(),
            });
        }
        let host = url.host_str().ok_or_else(|| Error::Policy {
            operation: "network fetch".to_owned(),
            message: "URL has no host".to_owned(),
        })?;
        if !host_is_allowed(host, &self.policy.allowed_hosts) {
            return Err(Error::Policy {
                operation: "network fetch".to_owned(),
                message: format!("host {host} is not in the allowlist"),
            });
        }
        Ok(())
    }

    pub(super) fn download(&self, url: &Url) -> Result<Vec<u8>> {
        self.check_url(url)?;
        let client = self
            .client
            .as_ref()
            .expect("fetcher client is available while downloading");
        let mut response = client.get(url.clone()).send().map_err(|error| {
            let message = error.to_string();
            if error.is_redirect()
                || message.contains("redirect target is not allowed by network policy")
                || message.contains("redirect limit exceeded")
            {
                Error::Policy {
                    operation: "network redirect".to_owned(),
                    message,
                }
            } else {
                Error::Fetch {
                    package: "artifact".to_owned(),
                    source_url: url.to_string(),
                    message,
                }
            }
        })?;
        self.check_url(response.url())?;
        if !response.status().is_success() {
            return Err(Error::Fetch {
                package: "artifact".to_owned(),
                source_url: url.to_string(),
                message: format!("HTTP {}", response.status()),
            });
        }
        if let Some(length) = response.content_length()
            && length > self.limits.max_archive_bytes
        {
            return Err(Error::LimitExceeded {
                resource: "download bytes".to_owned(),
                limit: self.limits.max_archive_bytes,
            });
        }
        let mut bytes = Vec::new();
        response
            .by_ref()
            .take(self.limits.max_archive_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|source| Error::Io {
                operation: "read HTTP response".to_owned(),
                path: PathBuf::from(url.as_str()),
                source,
            })?;
        if bytes.len() as u64 > self.limits.max_archive_bytes {
            return Err(Error::LimitExceeded {
                resource: "download bytes".to_owned(),
                limit: self.limits.max_archive_bytes,
            });
        }
        Ok(bytes)
    }

    fn python_artifact_url(&self, dependency: &Dependency) -> Result<Url> {
        if let Some(url) = &dependency.source_url {
            return Url::parse(url).map_err(|error| Error::Resolution {
                package: dependency.id(),
                message: error.to_string(),
            });
        }
        let version = dependency
            .resolved_version
            .as_deref()
            .ok_or_else(|| Error::Resolution {
                package: dependency.id(),
                message: "locked version is missing".to_owned(),
            })?;
        let api = Url::parse(&format!(
            "https://pypi.org/pypi/{}/{version}/json",
            dependency.name
        ))
        .expect("static PyPI URL is valid");
        let metadata: JsonValue =
            serde_json::from_slice(&self.download(&api)?).map_err(|error| Error::Resolution {
                package: dependency.id(),
                message: format!("invalid PyPI response: {error}"),
            })?;
        let expected = dependency
            .integrity
            .as_deref()
            .and_then(|value| value.strip_prefix("sha256:"));
        let candidates = metadata
            .get("urls")
            .and_then(JsonValue::as_array)
            .ok_or_else(|| Error::Resolution {
                package: dependency.id(),
                message: "PyPI response has no artifacts".to_owned(),
            })?;
        let artifact = candidates
            .iter()
            .find(|item| {
                let digest = item
                    .get("digests")
                    .and_then(|value| value.get("sha256"))
                    .and_then(JsonValue::as_str);
                expected.is_some_and(|expected| digest == Some(expected))
            })
            .or_else(|| {
                candidates.iter().find(|item| {
                    item.get("packagetype").and_then(JsonValue::as_str) == Some("sdist")
                })
            })
            .or_else(|| candidates.first())
            .ok_or_else(|| Error::Resolution {
                package: dependency.id(),
                message: "PyPI response has no usable artifact".to_owned(),
            })?;
        let raw = artifact
            .get("url")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| Error::Resolution {
                package: dependency.id(),
                message: "artifact URL is missing".to_owned(),
            })?;
        Url::parse(raw).map_err(|error| Error::Resolution {
            package: dependency.id(),
            message: error.to_string(),
        })
    }

    pub(super) fn artifact_url(&self, dependency: &Dependency) -> Result<Url> {
        if dependency.ecosystem == Ecosystem::Python {
            return self.python_artifact_url(dependency);
        }
        if dependency.ecosystem == Ecosystem::Deno && dependency.requirement.starts_with("npm:") {
            let version =
                dependency
                    .resolved_version
                    .as_deref()
                    .ok_or_else(|| Error::Resolution {
                        package: dependency.id(),
                        message: "Deno npm dependency has no locked version".to_owned(),
                    })?;
            let spec = dependency.requirement.trim_start_matches("npm:");
            let name = spec.rsplit_once('@').map_or(spec, |(name, _)| name);
            let base = name.rsplit('/').next().unwrap_or(name);
            return Url::parse(&format!(
                "https://registry.npmjs.org/{name}/-/{base}-{version}.tgz"
            ))
            .map_err(|error| Error::Resolution {
                package: dependency.id(),
                message: error.to_string(),
            });
        }
        let raw = dependency
            .source_url
            .as_deref()
            .or_else(|| {
                if dependency.ecosystem == Ecosystem::Deno
                    && dependency.requirement.starts_with("http")
                {
                    Some(dependency.requirement.as_str())
                } else {
                    None
                }
            })
            .ok_or_else(|| Error::Resolution {
                package: dependency.id(),
                message: "lockfile did not provide an artifact URL".to_owned(),
            })?;
        Url::parse(raw).map_err(|error| Error::Resolution {
            package: dependency.id(),
            message: error.to_string(),
        })
    }
}

fn npm_package_and_requirement(dependency: &Dependency) -> (String, String) {
    let raw = if dependency.ecosystem == Ecosystem::Deno {
        dependency
            .requirement
            .strip_prefix("npm:")
            .unwrap_or(&dependency.requirement)
    } else if dependency.requirement.starts_with("npm:") {
        dependency.requirement.trim_start_matches("npm:")
    } else {
        return (dependency.name.clone(), dependency.requirement.clone());
    };
    match raw.rsplit_once('@') {
        Some((name, requirement)) if !name.is_empty() => (name.to_owned(), requirement.to_owned()),
        _ => (raw.to_owned(), "*".to_owned()),
    }
}

fn resolve_npm_release(
    dependency: &mut Dependency,
    requirement: String,
    metadata: &JsonValue,
) -> Result<()> {
    let versions = metadata
        .get("versions")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| Error::Resolution {
            package: dependency.id(),
            message: "npm registry response has no versions".to_owned(),
        })?;
    let range = NpmRange::from_str(&requirement).ok();
    let tagged_version = range.is_none().then(|| {
        metadata
            .get("dist-tags")
            .and_then(|tags| tags.get(&requirement))
            .and_then(JsonValue::as_str)
    });
    let selected = if let Some(range) = range {
        versions
            .iter()
            .filter_map(|(raw_version, release)| {
                let version = NpmVersion::from_str(raw_version).ok()?;
                range.satisfies(&version).then_some((version, release))
            })
            .max_by(|(left, _), (right, _)| left.cmp(right))
            .map(|(version, release)| (version.to_string(), release))
    } else {
        tagged_version.flatten().and_then(|version| {
            versions
                .get(version)
                .map(|release| (version.to_owned(), release))
        })
    }
    .ok_or_else(|| Error::Resolution {
        package: dependency.id(),
        message: format!("npm registry has no release satisfying {requirement}"),
    })?;

    let dist = selected.1.get("dist").ok_or_else(|| Error::Resolution {
        package: dependency.id(),
        message: format!("npm release {} has no distribution metadata", selected.0),
    })?;
    let tarball = dist
        .get("tarball")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| Error::Resolution {
            package: dependency.id(),
            message: format!("npm release {} has no tarball URL", selected.0),
        })?;
    let integrity = dist
        .get("integrity")
        .and_then(JsonValue::as_str)
        .filter(|integrity| integrity.starts_with("sha256-") || integrity.starts_with("sha512-"))
        .ok_or_else(|| Error::Resolution {
            package: dependency.id(),
            message: format!(
                "npm release {} has no supported SHA-256 or SHA-512 integrity",
                selected.0
            ),
        })?;
    dependency.resolved_version = Some(selected.0);
    dependency.source_url = Some(tarball.to_owned());
    dependency.integrity = Some(integrity.to_owned());
    Ok(())
}

fn resolve_python_release(dependency: &mut Dependency, metadata: &JsonValue) -> Result<()> {
    let specifier = python_specifier(dependency)?;
    let releases = metadata
        .get("releases")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| Error::Resolution {
            package: dependency.id(),
            message: "PyPI response has no releases".to_owned(),
        })?;

    let selected = releases
        .iter()
        .filter_map(|(raw_version, files)| {
            let version = Version::from_str(raw_version).ok()?;
            if specifier
                .as_ref()
                .is_some_and(|specifier| !specifier.contains(&version))
            {
                return None;
            }
            let artifact = select_python_artifact(files.as_array()?)?;
            Some((version, raw_version, artifact))
        })
        .max_by(|(left, ..), (right, ..)| left.cmp(right))
        .ok_or_else(|| Error::Resolution {
            package: dependency.id(),
            message: format!(
                "PyPI has no non-yanked artifact satisfying {}",
                dependency.requirement
            ),
        })?;

    let raw_url = selected
        .2
        .get("url")
        .and_then(JsonValue::as_str)
        .expect("selected Python artifact has a URL");
    let digest = selected
        .2
        .get("digests")
        .and_then(|digests| digests.get("sha256"))
        .and_then(JsonValue::as_str)
        .expect("selected Python artifact has a SHA-256 digest");
    dependency.resolved_version = Some(selected.1.to_owned());
    dependency.source_url = Some(raw_url.to_owned());
    dependency.integrity = Some(format!("sha256:{digest}"));
    Ok(())
}

fn python_specifier(dependency: &Dependency) -> Result<Option<VersionSpecifiers>> {
    let requirement = dependency
        .requirement
        .split(';')
        .next()
        .unwrap_or(&dependency.requirement)
        .trim();
    let mut raw = requirement
        .strip_prefix(&dependency.name)
        .unwrap_or(requirement)
        .trim();
    if raw.starts_with('[')
        && let Some(end) = raw.find(']')
    {
        raw = raw[end + 1..].trim();
    }
    if raw.is_empty() || raw == "*" {
        return Ok(None);
    }
    VersionSpecifiers::from_str(raw)
        .map(Some)
        .map_err(|error| Error::Resolution {
            package: dependency.id(),
            message: format!("unsupported Python version requirement {raw:?}: {error}"),
        })
}

fn select_python_artifact(files: &[JsonValue]) -> Option<&JsonValue> {
    let usable = |file: &&JsonValue| {
        !file
            .get("yanked")
            .and_then(JsonValue::as_bool)
            .unwrap_or(false)
            && file.get("url").and_then(JsonValue::as_str).is_some()
            && file
                .get("digests")
                .and_then(|digests| digests.get("sha256"))
                .and_then(JsonValue::as_str)
                .is_some_and(|digest| {
                    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
    };
    files
        .iter()
        .filter(usable)
        .find(|file| file.get("packagetype").and_then(JsonValue::as_str) == Some("sdist"))
        .or_else(|| files.iter().find(usable))
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::atomic::{AtomicU64, Ordering},
        thread,
        time::Duration,
    };

    use serde_json::json;
    use url::Url;

    use super::{
        SafeSourceFetcher, npm_package_and_requirement, resolve_npm_release, resolve_python_release,
    };
    use crate::{
        error::Error,
        fetcher::FetchPolicy,
        model::{Dependency, Ecosystem, EngineLimits},
    };

    static TEST_CACHE_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_fetcher(allowed_hosts: Vec<&str>, max_archive_bytes: u64) -> SafeSourceFetcher {
        let cache = std::env::temp_dir().join(format!(
            "chainsec-network-test-{}-{}",
            std::process::id(),
            TEST_CACHE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let policy = FetchPolicy {
            offline: false,
            allowed_hosts: allowed_hosts.into_iter().map(str::to_owned).collect(),
            request_timeout: Duration::from_secs(2),
            ..FetchPolicy::default()
        };
        let limits = EngineLimits {
            max_archive_bytes,
            ..EngineLimits::default()
        };
        SafeSourceFetcher::new(cache, policy, limits).unwrap()
    }

    fn spawn_server(listener: TcpListener, responses: Vec<Vec<u8>>) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                read_request(&mut stream);
                stream.write_all(&response).unwrap();
                stream.flush().unwrap();
            }
        })
    }

    fn read_request(stream: &mut TcpStream) {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 512];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let bytes = stream.read(&mut buffer).unwrap();
            assert_ne!(
                bytes, 0,
                "client closed connection before sending a request"
            );
            request.extend_from_slice(&buffer[..bytes]);
        }
    }

    fn response(headers: &str, body: &[u8]) -> Vec<u8> {
        let mut response =
            format!("HTTP/1.1 200 OK\r\nConnection: close\r\n{headers}\r\n").into_bytes();
        response.extend_from_slice(body);
        response
    }

    #[test]
    fn download_allows_same_host_redirect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = spawn_server(
            listener,
            vec![
                format!(
                    "HTTP/1.1 302 Found\r\nConnection: close\r\nLocation: http://127.0.0.1:{port}/artifact\r\nContent-Length: 0\r\n\r\n"
                )
                .into_bytes(),
                response("Content-Length: 2\r\n", b"ok"),
            ],
        );
        let fetcher = test_fetcher(vec!["127.0.0.1"], 16);
        let url = Url::parse(&format!("http://127.0.0.1:{port}/start")).unwrap();

        assert_eq!(fetcher.download(&url).unwrap(), b"ok");
        server.join().unwrap();
    }

    #[test]
    fn download_rejects_redirect_to_unallowed_host_as_policy() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = spawn_server(
            listener,
            vec![format!(
                "HTTP/1.1 302 Found\r\nConnection: close\r\nLocation: http://localhost:{port}/blocked\r\nContent-Length: 0\r\n\r\n"
            )
            .into_bytes()],
        );
        let fetcher = test_fetcher(vec!["127.0.0.1"], 16);
        let url = Url::parse(&format!("http://127.0.0.1:{port}/start")).unwrap();

        let error = fetcher.download(&url).unwrap_err();
        assert!(matches!(error, Error::Policy { operation, .. }
            if operation == "network redirect"));
        server.join().unwrap();
    }

    #[test]
    fn download_rejects_oversized_content_length() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = spawn_server(listener, vec![response("Content-Length: 4\r\n", b"")]);
        let fetcher = test_fetcher(vec!["127.0.0.1"], 3);
        let url = Url::parse(&format!("http://127.0.0.1:{port}/artifact")).unwrap();

        assert!(
            matches!(fetcher.download(&url), Err(Error::LimitExceeded { resource, limit })
            if resource == "download bytes" && limit == 3)
        );
        server.join().unwrap();
    }

    #[test]
    fn download_rejects_oversized_streamed_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = spawn_server(listener, vec![response("", b"four")]);
        let fetcher = test_fetcher(vec!["127.0.0.1"], 3);
        let url = Url::parse(&format!("http://127.0.0.1:{port}/artifact")).unwrap();

        assert!(
            matches!(fetcher.download(&url), Err(Error::LimitExceeded { resource, limit })
            if resource == "download bytes" && limit == 3)
        );
        server.join().unwrap();
    }

    #[test]
    fn download_rejects_unallowed_initial_url_before_connecting() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let fetcher = test_fetcher(vec!["example.com"], 16);
        let url = Url::parse(&format!("http://127.0.0.1:{port}/artifact")).unwrap();

        assert!(
            matches!(fetcher.download(&url), Err(Error::Policy { operation, message })
            if operation == "network fetch" && message.contains("not in the allowlist"))
        );
        listener.set_nonblocking(true).unwrap();
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }

    #[test]
    fn unlocked_npm_resolution_selects_highest_matching_integrity_pinned_release() {
        let mut dependency = Dependency::declared(Ecosystem::Npm, "example", "^2.8.3");
        let metadata = json!({
            "dist-tags": {"latest": "3.0.0"},
            "versions": {
                "2.8.3": {"dist": {
                    "tarball": "https://registry.npmjs.org/example/-/example-2.8.3.tgz",
                    "integrity": "sha512-old"
                }},
                "2.9.0": {"dist": {
                    "tarball": "https://registry.npmjs.org/example/-/example-2.9.0.tgz",
                    "integrity": "sha512-selected"
                }},
                "3.0.0": {"dist": {
                    "tarball": "https://registry.npmjs.org/example/-/example-3.0.0.tgz",
                    "integrity": "sha512-new-major"
                }}
            }
        });

        resolve_npm_release(&mut dependency, "^2.8.3".to_owned(), &metadata).unwrap();

        assert_eq!(dependency.resolved_version.as_deref(), Some("2.9.0"));
        assert_eq!(
            dependency.source_url.as_deref(),
            Some("https://registry.npmjs.org/example/-/example-2.9.0.tgz")
        );
        assert_eq!(dependency.integrity.as_deref(), Some("sha512-selected"));
    }

    #[test]
    fn npm_alias_and_deno_specs_resolve_the_registry_package_name() {
        let npm_alias = Dependency::declared(Ecosystem::Npm, "alias", "npm:@scope/real@~1.2.0");
        let deno = Dependency::declared(Ecosystem::Deno, "alias", "npm:@scope/real@~1.2.0");

        assert_eq!(
            npm_package_and_requirement(&npm_alias),
            ("@scope/real".to_owned(), "~1.2.0".to_owned())
        );
        assert_eq!(
            npm_package_and_requirement(&deno),
            ("@scope/real".to_owned(), "~1.2.0".to_owned())
        );
    }

    #[test]
    fn unlocked_python_resolution_selects_highest_matching_sdist() {
        let mut dependency = Dependency::declared(
            Ecosystem::Python,
            "example",
            "example>=1.0,<2; python_version > '3'",
        );
        let digest = "a".repeat(64);
        let metadata = json!({
            "releases": {
                "1.0": [{
                    "packagetype": "bdist_wheel",
                    "url": "https://files.pythonhosted.org/example-1.0.whl",
                    "digests": {"sha256": digest}
                }],
                "1.9": [{
                    "packagetype": "sdist",
                    "url": "https://files.pythonhosted.org/example-1.9.tar.gz",
                    "digests": {"sha256": "b".repeat(64)}
                }],
                "2.0": [{
                    "packagetype": "sdist",
                    "url": "https://files.pythonhosted.org/example-2.0.tar.gz",
                    "digests": {"sha256": "c".repeat(64)}
                }]
            }
        });

        resolve_python_release(&mut dependency, &metadata).unwrap();

        assert_eq!(dependency.resolved_version.as_deref(), Some("1.9"));
        assert_eq!(
            dependency.source_url.as_deref(),
            Some("https://files.pythonhosted.org/example-1.9.tar.gz")
        );
        assert_eq!(
            dependency.integrity,
            Some(format!("sha256:{}", "b".repeat(64)))
        );
    }
}
