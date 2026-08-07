use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    fs::{self, File},
    io::Write,
    path::{Component, Path, PathBuf},
};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use tree_sitter::Parser;
use url::Url;

use crate::error::{Error, Result};

use super::{
    SafeSourceFetcher,
    archive::{ExtractionStats, check_extraction_limits, safe_relative},
    integrity::{verify_integrity, verify_jsr_checksum},
};

#[derive(Debug, Deserialize)]
struct JsrVersionMetadata {
    manifest: BTreeMap<String, JsrManifestEntry>,
}

#[derive(Debug, Deserialize)]
struct JsrManifestEntry {
    size: u64,
    checksum: String,
}

impl SafeSourceFetcher {
    pub(super) fn fetch_jsr_package(
        &self,
        metadata_url: &Url,
        temporary: &Path,
        expected: Option<&str>,
    ) -> Result<(PathBuf, String, ExtractionStats)> {
        let metadata_bytes = self.download(metadata_url)?;
        verify_integrity(&metadata_bytes, expected, metadata_url.as_str())?;
        let metadata: JsrVersionMetadata =
            serde_json::from_slice(&metadata_bytes).map_err(|error| Error::Fetch {
                package: "jsr package".to_owned(),
                source_url: metadata_url.to_string(),
                message: format!("invalid JSR version metadata: {error}"),
            })?;
        let declared_bytes = metadata
            .manifest
            .values()
            .try_fold(0u64, |total, entry| total.checked_add(entry.size))
            .ok_or_else(|| Error::LimitExceeded {
                resource: "JSR package bytes".to_owned(),
                limit: self.limits.max_extracted_bytes,
            })?;
        if metadata.manifest.len() as u64 > self.limits.max_extracted_files {
            return Err(Error::LimitExceeded {
                resource: "JSR package files".to_owned(),
                limit: self.limits.max_extracted_files,
            });
        }
        if declared_bytes > self.limits.max_extracted_bytes {
            return Err(Error::LimitExceeded {
                resource: "JSR package bytes".to_owned(),
                limit: self.limits.max_extracted_bytes,
            });
        }
        let source = temporary.join("source");
        fs::create_dir_all(&source).map_err(|source_error| Error::Io {
            operation: "create JSR source directory".to_owned(),
            path: source.clone(),
            source: source_error,
        })?;
        let base = metadata_url
            .as_str()
            .strip_suffix("_meta.json")
            .ok_or_else(|| Error::Resolution {
                package: "jsr package".to_owned(),
                message: "JSR metadata URL does not end in _meta.json".to_owned(),
            })?;
        let mut stats = ExtractionStats::default();
        for (manifest_path, entry) in metadata.manifest {
            let raw = manifest_path
                .strip_prefix('/')
                .ok_or_else(|| Error::Policy {
                    operation: "JSR extraction".to_owned(),
                    message: format!("JSR manifest path must begin with /: {manifest_path}"),
                })?;
            if raw.is_empty() || raw.contains('\\') {
                return Err(Error::Policy {
                    operation: "JSR extraction".to_owned(),
                    message: format!("unsafe JSR manifest path: {manifest_path}"),
                });
            }
            let relative = Path::new(raw);
            if !safe_relative(relative)
                || relative
                    .components()
                    .any(|component| matches!(component, Component::CurDir))
            {
                return Err(Error::Policy {
                    operation: "JSR extraction".to_owned(),
                    message: format!("unsafe JSR manifest path: {manifest_path}"),
                });
            }
            let mut file_url =
                Url::parse(&format!("{base}/")).map_err(|error| Error::Resolution {
                    package: "jsr package".to_owned(),
                    message: error.to_string(),
                })?;
            {
                let mut segments = file_url
                    .path_segments_mut()
                    .map_err(|_| Error::Resolution {
                        package: "jsr package".to_owned(),
                        message: "JSR URL cannot contain path segments".to_owned(),
                    })?;
                segments.pop_if_empty();
                for component in relative.components() {
                    if let Component::Normal(value) = component {
                        let value = value.to_str().ok_or_else(|| Error::Policy {
                            operation: "JSR extraction".to_owned(),
                            message: "JSR manifest path is not UTF-8".to_owned(),
                        })?;
                        segments.push(value);
                    }
                }
            }
            let bytes = self.download(&file_url)?;
            if bytes.len() as u64 != entry.size {
                return Err(Error::Fetch {
                    package: "jsr package".to_owned(),
                    source_url: file_url.to_string(),
                    message: format!(
                        "size mismatch: expected {}, received {}",
                        entry.size,
                        bytes.len()
                    ),
                });
            }
            verify_jsr_checksum(&bytes, &entry.checksum, file_url.as_str())?;
            stats.files += 1;
            stats.bytes = stats.bytes.saturating_add(bytes.len() as u64);
            check_extraction_limits(&stats, &self.limits)?;
            let output = source.join(relative);
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent).map_err(|source_error| Error::Io {
                    operation: "create JSR source directory".to_owned(),
                    path: parent.to_owned(),
                    source: source_error,
                })?;
            }
            let mut file = File::options()
                .write(true)
                .create_new(true)
                .open(&output)
                .map_err(|source_error| Error::Io {
                    operation: "create JSR source file".to_owned(),
                    path: output.clone(),
                    source: source_error,
                })?;
            file.write_all(&bytes).map_err(|source_error| Error::Io {
                operation: "write JSR source file".to_owned(),
                path: output,
                source: source_error,
            })?;
        }
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&metadata_bytes)));
        Ok((source, digest, stats))
    }

    pub(super) fn fetch_deno_graph(
        &self,
        root_url: &Url,
        temporary: &Path,
        expected: Option<&str>,
        lockfile: Option<&Path>,
    ) -> Result<(PathBuf, String, ExtractionStats)> {
        let remote_integrities = if let Some(lockfile) = lockfile {
            let lock = fs::read_to_string(lockfile).map_err(|source| Error::Io {
                operation: "read Deno lockfile".to_owned(),
                path: lockfile.to_owned(),
                source,
            })?;
            let value: serde_json::Value =
                serde_json::from_str(&lock).map_err(|error| Error::Fetch {
                    package: "Deno graph".to_owned(),
                    source_url: lockfile.display().to_string(),
                    message: format!("invalid Deno lockfile: {error}"),
                })?;
            Some(
                value
                    .get("remote")
                    .and_then(serde_json::Value::as_object)
                    .map(|remote| {
                        remote
                            .iter()
                            .filter_map(|(url, integrity)| {
                                integrity
                                    .as_str()
                                    .map(|integrity| (url.clone(), integrity.to_owned()))
                            })
                            .collect::<std::collections::HashMap<_, _>>()
                    })
                    .unwrap_or_default(),
            )
        } else {
            None
        };
        let source = temporary.join("source");
        fs::create_dir_all(&source).map_err(|source_error| Error::Io {
            operation: "create Deno graph directory".to_owned(),
            path: source.clone(),
            source: source_error,
        })?;
        let mut queue = VecDeque::from([root_url.clone()]);
        let mut visited = HashSet::new();
        let mut stats = ExtractionStats::default();
        let mut root_digest = String::new();
        while let Some(url) = queue.pop_front() {
            let canonical = url.to_string();
            if !visited.insert(canonical.clone()) {
                continue;
            }
            if visited.len() > self.policy.max_deno_modules {
                return Err(Error::LimitExceeded {
                    resource: "Deno graph modules".to_owned(),
                    limit: self.policy.max_deno_modules as u64,
                });
            }
            let bytes = self.download(&url)?;
            let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
            verify_graph_module_integrity(
                &bytes,
                &url,
                root_url,
                expected,
                remote_integrities.as_ref(),
            )?;
            if url == *root_url {
                root_digest = digest;
            }
            stats.files += 1;
            stats.bytes += bytes.len() as u64;
            check_extraction_limits(&stats, &self.limits)?;
            let extension = Path::new(url.path())
                .extension()
                .and_then(|value| value.to_str())
                .filter(|value| {
                    matches!(
                        *value,
                        "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts"
                    )
                })
                .unwrap_or("ts");
            let filename = format!(
                "{}.{}",
                hex::encode(Sha256::digest(canonical.as_bytes())),
                extension
            );
            fs::write(source.join(filename), &bytes).map_err(|source_error| Error::Io {
                operation: "write Deno module".to_owned(),
                path: source.clone(),
                source: source_error,
            })?;
            for specifier in static_module_specifiers(&bytes, extension) {
                let next = if specifier.starts_with("http://") || specifier.starts_with("https://")
                {
                    Url::parse(&specifier).ok()
                } else if specifier.starts_with("./")
                    || specifier.starts_with("../")
                    || specifier.starts_with('/')
                {
                    url.join(&specifier).ok()
                } else {
                    // Bare, npm:, jsr:, data:, node:, and custom-loader specifiers
                    // are resolved by Deno, not as URL modules by this fetcher.
                    None
                };
                if let Some(next) = next.filter(|next| matches!(next.scheme(), "http" | "https")) {
                    queue.push_back(next);
                }
            }
        }
        Ok((source, root_digest, stats))
    }
}

fn verify_graph_module_integrity(
    bytes: &[u8],
    url: &Url,
    root_url: &Url,
    expected: Option<&str>,
    remote_integrities: Option<&std::collections::HashMap<String, String>>,
) -> Result<()> {
    if url == root_url {
        verify_integrity(bytes, expected, root_url.as_str())?;
    }
    if let Some(remote_integrities) = remote_integrities {
        let locked = remote_integrities.get(url.as_str()).map(String::as_str);
        verify_integrity(bytes, locked, url.as_str())?;
    }
    Ok(())
}

fn static_module_specifiers(source: &[u8], extension: &str) -> Vec<String> {
    let language = match extension {
        "tsx" => tree_sitter_typescript::LANGUAGE_TSX.into(),
        "ts" | "mts" | "cts" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        _ => tree_sitter_javascript::LANGUAGE.into(),
    };
    let mut parser = Parser::new();
    if parser.set_language(&language).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let mut result = Vec::new();
    collect_static_module_specifiers(tree.root_node(), source, &mut result);
    result
}

fn collect_static_module_specifiers(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    result: &mut Vec<String>,
) {
    if matches!(node.kind(), "import_statement" | "export_statement")
        && let Some(source_node) = node.child_by_field_name("source")
        && let Some(specifier) = string_literal_value(source_node, source)
    {
        result.push(specifier);
    }
    if node.kind() == "call_expression"
        && node
            .child_by_field_name("function")
            .is_some_and(|function| function.utf8_text(source).ok() == Some("import"))
        && let Some(arguments) = node.child_by_field_name("arguments")
        && let Some(argument) = arguments.named_child(0)
        && let Some(specifier) = string_literal_value(argument, source)
    {
        result.push(specifier);
    }
    for child in node.named_children(&mut node.walk()) {
        collect_static_module_specifiers(child, source, result);
    }
}

fn string_literal_value(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    if node.kind() != "string" {
        return None;
    }
    let raw = node.utf8_text(source).ok()?;
    let value = raw.strip_prefix(['"', '\''])?.strip_suffix(['"', '\''])?;
    // Avoid treating escaped or malformed literals as URL specifiers. This keeps
    // computed/template and escape-dependent resolution out of the URL graph.
    (!value.contains('\\')).then(|| value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn integrity(bytes: &[u8]) -> String {
        format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
    }

    #[test]
    fn graph_root_integrity_is_checked_even_with_a_lockfile() {
        let root = Url::parse("https://example.test/root.ts").unwrap();
        let mut locked = std::collections::HashMap::new();
        locked.insert(root.to_string(), integrity(b"root"));

        let error = verify_graph_module_integrity(
            b"changed",
            &root,
            &root,
            Some(&integrity(b"root")),
            Some(&locked),
        )
        .unwrap_err();
        assert!(error.to_string().contains("integrity verification failed"));
    }

    #[test]
    fn graph_modules_require_lockfile_integrity_when_lockfile_is_present() {
        let root = Url::parse("https://example.test/root.ts").unwrap();
        let child = Url::parse("https://example.test/child.ts").unwrap();
        let mut locked = std::collections::HashMap::new();
        locked.insert(root.to_string(), integrity(b"root"));

        let error = verify_graph_module_integrity(
            b"child",
            &child,
            &root,
            Some(&integrity(b"root")),
            Some(&locked),
        )
        .unwrap_err();
        assert!(error.to_string().contains("has no expected integrity"));
    }
}
