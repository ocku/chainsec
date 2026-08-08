use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use tree_sitter::Parser;
use url::Url;

use crate::error::{Error, Result};

use crate::fetcher::{
    SourceFetcher,
    archive::{ExtractionStats, check_extraction_limits},
    integrity::verify_integrity,
};

impl SourceFetcher {
    pub(in crate::fetcher) async fn fetch_deno_graph(
        &self,
        root_url: &Url,
        temporary: &Path,
        expected: Option<&str>,
        lockfile: Option<&Path>,
    ) -> Result<(PathBuf, String, ExtractionStats)> {
        let remote_integrities = read_remote_integrities(lockfile)?;
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
            let bytes = self.download(&url).await?;
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
            let extension = module_extension(&url);
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
            queue.extend(
                static_module_specifiers(&bytes, extension)
                    .into_iter()
                    .filter_map(|specifier| resolve_remote_module(&url, &specifier)),
            );
        }
        Ok((source, root_digest, stats))
    }
}

fn read_remote_integrities(lockfile: Option<&Path>) -> Result<Option<HashMap<String, String>>> {
    let Some(lockfile) = lockfile else {
        return Ok(None);
    };
    let lock = fs::read_to_string(lockfile).map_err(|source| Error::Io {
        operation: "read Deno lockfile".to_owned(),
        path: lockfile.to_owned(),
        source,
    })?;
    let value: serde_json::Value = serde_json::from_str(&lock).map_err(|error| Error::Fetch {
        package: "Deno graph".to_owned(),
        source_url: lockfile.display().to_string(),
        message: format!("invalid Deno lockfile: {error}"),
    })?;
    Ok(Some(
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
                    .collect()
            })
            .unwrap_or_default(),
    ))
}

fn verify_graph_module_integrity(
    bytes: &[u8],
    url: &Url,
    root_url: &Url,
    expected: Option<&str>,
    remote_integrities: Option<&HashMap<String, String>>,
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

fn module_extension(url: &Url) -> &str {
    Path::new(url.path())
        .extension()
        .and_then(|value| value.to_str())
        .filter(|value| {
            matches!(
                *value,
                "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts"
            )
        })
        .unwrap_or("ts")
}

fn resolve_remote_module(base: &Url, specifier: &str) -> Option<Url> {
    let module = if specifier.starts_with("http://") || specifier.starts_with("https://") {
        Url::parse(specifier).ok()
    } else if specifier.starts_with("./")
        || specifier.starts_with("../")
        || specifier.starts_with('/')
    {
        base.join(specifier).ok()
    } else {
        // Bare, npm:, jsr:, data:, node:, and custom-loader specifiers are resolved by
        // Deno, not as URL modules by this fetcher.
        None
    };
    module.filter(|url| matches!(url.scheme(), "http" | "https"))
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
        let mut locked = HashMap::new();
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
        let mut locked = HashMap::new();
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
