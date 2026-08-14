use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    error::{Error, Result},
    fetcher::{
        SourceFetcher,
        archive::{ExtractionStats, account_extracted_entry},
        cache::is_unsafe_cache_open_error,
        filesystem::TrustedDir,
    },
};

use crate::model::DenoLockfileSnapshot;

use super::{
    canonical_graph_url, enqueue_graph_module, graph_redirect_filename, module_extension,
    resolve_graph_modules_with_sink, verify_graph_module_integrity, write_graph_redirect,
};

impl SourceFetcher {
    pub(in crate::fetcher) fn rebuild_cached_deno_graph(
        &self,
        root_url: &Url,
        temporary: &Path,
        expected: Option<&str>,
        lockfile: Option<&DenoLockfileSnapshot>,
        cached_source: &Path,
    ) -> Result<(PathBuf, String, ExtractionStats)> {
        let source = self.create_workspace_subdirectory(
            temporary,
            Path::new("source"),
            "create reconstructed Deno graph directory",
        )?;
        let source_root = TrustedDir::open(&source).map_err(|source_error| Error::Io {
            operation: "open reconstructed Deno graph directory".to_owned(),
            path: source.clone(),
            source: source_error,
        })?;
        let cached_root = open_cached_directory(cached_source, "cached Deno graph")?;
        let mut queue = VecDeque::from([root_url.clone()]);
        let mut queued = HashSet::from([canonical_graph_url(root_url)]);
        let mut materialized = HashMap::<String, Vec<u8>>::new();
        let mut stats = ExtractionStats::default();
        let mut root_digest = String::new();
        while let Some(requested_url) = queue.pop_front() {
            let is_root = requested_url == *root_url;
            // The root was selected before cache lookup, and reconstruction never
            // performs network I/O. Its origin is therefore already authorized by
            // selection; keep same-origin cached modules usable after a policy change.
            // Cross-origin imports remain subject to the host policy so cache contents
            // cannot extend the graph's authority.
            let enforce_host_policy = requested_url.origin() != root_url.origin();
            if enforce_host_policy {
                self.check_url_policy(&requested_url, false)?;
            }
            let url = self.cached_graph_effective_url(
                &cached_root,
                cached_source,
                &requested_url,
                enforce_host_policy,
            )?;
            let canonical = canonical_graph_url(&url);

            if let Some(bytes) = materialized.get(&canonical) {
                let digest = self.verify_reconstructed_graph_module(
                    bytes,
                    &requested_url,
                    &url,
                    is_root,
                    root_url,
                    expected,
                    lockfile,
                )?;
                if is_root {
                    root_digest = digest;
                }
                self.write_reconstructed_graph_redirect_if_needed(
                    &source_root,
                    &source,
                    &requested_url,
                    &url,
                    &mut stats,
                )?;
                continue;
            }
            self.ensure_deno_module_capacity(materialized.len())?;

            let extension = module_extension(&url);
            let filename = cached_graph_module_filename(&canonical, extension);
            let bytes = read_cached_graph_module(
                &cached_root,
                cached_source,
                &filename,
                self.limits.max_archive_size,
            )?;
            let digest = self.verify_reconstructed_graph_module(
                &bytes,
                &requested_url,
                &url,
                is_root,
                root_url,
                expected,
                lockfile,
            )?;
            if is_root {
                root_digest = digest;
            }
            self.write_reconstructed_graph_redirect_if_needed(
                &source_root,
                &source,
                &requested_url,
                &url,
                &mut stats,
            )?;
            self.write_reconstructed_graph_module(
                &source_root,
                &source,
                &filename,
                &bytes,
                &mut stats,
            )?;
            self.enqueue_reconstructed_graph_imports(
                &url,
                &bytes,
                extension,
                &mut queue,
                &mut queued,
            )?;
            materialized.insert(canonical, bytes);
        }
        Ok((source, root_digest, stats))
    }

    fn ensure_deno_module_capacity(&self, materialized_count: usize) -> Result<()> {
        if materialized_count >= self.limits.max_packages {
            return Err(Error::LimitExceeded {
                resource: "Deno graph modules".to_owned(),
                limit: self.limits.max_packages as u64,
            });
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_reconstructed_graph_module(
        &self,
        bytes: &[u8],
        requested_url: &Url,
        effective_url: &Url,
        is_root: bool,
        root_url: &Url,
        expected: Option<&str>,
        lockfile: Option<&DenoLockfileSnapshot>,
    ) -> Result<String> {
        verify_graph_module_integrity(
            bytes,
            requested_url,
            effective_url,
            is_root,
            root_url,
            expected,
            lockfile.map(DenoLockfileSnapshot::remote_integrities),
        )?;
        Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
    }

    fn write_reconstructed_graph_redirect_if_needed(
        &self,
        source_root: &TrustedDir,
        source: &Path,
        requested_url: &Url,
        effective_url: &Url,
        stats: &mut ExtractionStats,
    ) -> Result<()> {
        if requested_url != effective_url {
            self.write_reconstructed_graph_redirect(
                source_root,
                source,
                requested_url,
                effective_url,
                stats,
            )?;
        }
        Ok(())
    }

    fn write_reconstructed_graph_module(
        &self,
        source_root: &TrustedDir,
        source: &Path,
        filename: &str,
        bytes: &[u8],
        stats: &mut ExtractionStats,
    ) -> Result<()> {
        account_extracted_entry(stats, bytes.len() as u64, &self.limits)?;

        let output = source.join(filename);
        let mut file =
            source_root
                .create_new_file(Path::new(filename))
                .map_err(|source_error| Error::Io {
                    operation: "create reconstructed Deno module".to_owned(),
                    path: output.clone(),
                    source: source_error,
                })?;
        file.write_all(bytes).map_err(|source_error| Error::Io {
            operation: "write reconstructed Deno module".to_owned(),
            path: output,
            source: source_error,
        })
    }

    fn enqueue_reconstructed_graph_imports(
        &self,
        url: &Url,
        bytes: &[u8],
        extension: &str,
        queue: &mut VecDeque<Url>,
        queued: &mut HashSet<String>,
    ) -> Result<()> {
        resolve_graph_modules_with_sink(url, bytes, extension, |module| {
            enqueue_graph_module(queue, queued, module, self.limits.max_packages)
        })
    }

    fn write_reconstructed_graph_redirect(
        &self,
        source_root: &TrustedDir,
        source: &Path,
        requested_url: &Url,
        effective_url: &Url,
        stats: &mut ExtractionStats,
    ) -> Result<()> {
        account_extracted_entry(stats, effective_url.as_str().len() as u64, &self.limits)?;
        write_graph_redirect(source_root, source, requested_url, effective_url)
    }

    fn cached_graph_effective_url(
        &self,
        cached_root: &TrustedDir,
        cached_source: &Path,
        requested_url: &Url,
        enforce_host_policy: bool,
    ) -> Result<Url> {
        let redirect_name = graph_redirect_filename(requested_url);
        let redirect_path = cached_source.join(&redirect_name);
        let bytes = match cached_root.open_file_no_follow(Path::new(&redirect_name)) {
            Ok(file) => read_bounded_file(file, &redirect_path, 8 * 1024)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(requested_url.clone());
            }
            Err(error) => {
                return Err(Error::Policy {
                    operation: "cache validation".to_owned(),
                    message: format!(
                        "cached Deno redirect is missing or unsafe: {}: {error}",
                        redirect_path.display()
                    ),
                });
            }
        };
        let text = std::str::from_utf8(&bytes).map_err(|error| Error::Policy {
            operation: "cache validation".to_owned(),
            message: format!("cached Deno redirect is invalid UTF-8: {error}"),
        })?;
        let effective = Url::parse(text).map_err(|error| Error::Policy {
            operation: "cache validation".to_owned(),
            message: format!("cached Deno redirect URL is invalid: {error}"),
        })?;
        if enforce_host_policy {
            self.check_url_policy(&effective, false)?;
        }
        Ok(effective)
    }
}

fn cached_graph_module_filename(canonical_url: &str, extension: &str) -> String {
    format!(
        "{}.{}",
        hex::encode(Sha256::digest(canonical_url.as_bytes())),
        extension
    )
}

fn open_cached_directory(source: &Path, label: &str) -> Result<TrustedDir> {
    TrustedDir::open(source).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound || is_unsafe_cache_open_error(&error) {
            Error::Policy {
                operation: "cache validation".to_owned(),
                message: format!("{label} is missing or unsafe: {}", source.display()),
            }
        } else {
            Error::Io {
                operation: format!("open {label}"),
                path: source.to_owned(),
                source: error,
            }
        }
    })
}

pub(super) fn read_cached_graph_module(
    source: &TrustedDir,
    source_path: &Path,
    filename: &str,
    limit: u64,
) -> Result<Vec<u8>> {
    let path = source_path.join(filename);
    let file = source
        .open_file_no_follow(Path::new(filename))
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound || is_unsafe_cache_open_error(&error) {
                Error::Policy {
                    operation: "cache validation".to_owned(),
                    message: format!(
                        "cached Deno module is missing or unsafe: {}",
                        path.display()
                    ),
                }
            } else {
                Error::Io {
                    operation: "open cached Deno module".to_owned(),
                    path: path.clone(),
                    source: error,
                }
            }
        })?;
    let metadata = file.metadata().map_err(|source| Error::Io {
        operation: "inspect opened cached Deno module".to_owned(),
        path: path.clone(),
        source,
    })?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(Error::Policy {
            operation: "cache validation".to_owned(),
            message: format!(
                "cached Deno module is unsafe or exceeds the download limit: {}",
                path.display()
            ),
        });
    }

    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| Error::Io {
            operation: "read cached Deno module".to_owned(),
            path: path.clone(),
            source,
        })?;
    if (bytes.len() as u64) > limit {
        return Err(Error::LimitExceeded {
            resource: "cached Deno module bytes".to_owned(),
            limit,
        });
    }
    Ok(bytes)
}

fn read_bounded_file(file: fs::File, path: &Path, limit: u64) -> Result<Vec<u8>> {
    let metadata = file.metadata().map_err(|source| Error::Io {
        operation: "inspect cached Deno metadata".to_owned(),
        path: path.to_owned(),
        source,
    })?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(Error::Policy {
            operation: "cache validation".to_owned(),
            message: format!(
                "cached Deno metadata is not a bounded regular file: {}",
                path.display()
            ),
        });
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| Error::Io {
            operation: "read cached Deno metadata".to_owned(),
            path: path.to_owned(),
            source,
        })?;
    if bytes.len() as u64 > limit {
        return Err(Error::LimitExceeded {
            resource: "cached Deno metadata bytes".to_owned(),
            limit,
        });
    }
    Ok(bytes)
}
