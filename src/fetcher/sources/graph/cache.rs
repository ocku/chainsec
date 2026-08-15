use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::Write,
    path::{Path, PathBuf},
};

use url::Url;

use crate::{
    error::{Error, Result},
    fetcher::{
        SourceFetcher,
        archive::{ExtractionStats, account_extracted_entry},
        budget::AcquisitionDeadline,
        filesystem::TrustedDir,
        integrity::sha256_digest_raw_before,
    },
};

use crate::model::DenoLockfileSnapshot;

use super::{
    GraphIntegrity,
    cache_io::{
        cached_graph_module_filename, lockfile_redirect_effective_url, open_cached_directory,
        read_bounded_file, read_cached_graph_module_before,
    },
    canonical_graph_url, enqueue_graph_module, graph_redirect_filename, module_extension,
    resolve_graph_modules_with_sink, verify_graph_module_integrity_before,
    verify_graph_module_integrity_from_digest_before, verify_materialized_module_bytes,
    write_graph_redirect,
};

impl SourceFetcher {
    #[cfg(test)]
    pub(in crate::fetcher) fn rebuild_cached_deno_graph(
        &self,
        root_url: &Url,
        temporary: &Path,
        expected: Option<&str>,
        lockfile: Option<&DenoLockfileSnapshot>,
        cached_source: &Path,
    ) -> Result<(PathBuf, String, ExtractionStats)> {
        let deadline = self.network_budget().deadline_guard();
        self.rebuild_cached_deno_graph_before(
            root_url,
            temporary,
            expected,
            lockfile,
            cached_source,
            &deadline,
        )
    }

    pub(in crate::fetcher) fn rebuild_cached_deno_graph_before(
        &self,
        root_url: &Url,
        temporary: &Path,
        expected: Option<&str>,
        lockfile: Option<&DenoLockfileSnapshot>,
        cached_source: &Path,
        deadline: &AcquisitionDeadline,
    ) -> Result<(PathBuf, String, ExtractionStats)> {
        deadline.check()?;
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
        let mut materialized = HashMap::<String, [u8; 32]>::new();
        let mut stats = ExtractionStats::default();
        let mut root_digest = String::new();
        while let Some(requested_url) = queue.pop_front() {
            deadline.check()?;
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
                lockfile,
                enforce_host_policy,
                deadline,
            )?;
            let canonical = canonical_graph_url(&url);
            let binding = GraphIntegrity {
                requested_url: &requested_url,
                effective_url: &url,
                is_root,
                root_url,
                expected,
                remote_integrities: lockfile.map(DenoLockfileSnapshot::remote_integrities),
            };

            if let Some(stored_digest) = materialized.get(&canonical) {
                match verify_graph_module_integrity_from_digest_before(
                    stored_digest,
                    binding,
                    deadline,
                )? {
                    Some(()) => {}
                    None => {
                        verify_materialized_module_bytes(
                            &source_root,
                            &source,
                            &canonical,
                            self.limits.max_archive_size,
                            stored_digest,
                            binding,
                            deadline,
                        )?;
                    }
                }
                if is_root {
                    root_digest = format!("sha256:{}", hex::encode(stored_digest));
                }
                self.write_reconstructed_graph_redirect_if_needed(
                    &source_root,
                    &source,
                    &requested_url,
                    &url,
                    &mut stats,
                    deadline,
                )?;
                continue;
            }
            self.ensure_deno_module_capacity(materialized.len())?;

            let extension = module_extension(&url);
            let filename = cached_graph_module_filename(&canonical, extension);
            let bytes = read_cached_graph_module_before(
                &cached_root,
                cached_source,
                &filename,
                self.limits.max_archive_size,
                deadline,
            )?;
            let digest = self.verify_reconstructed_graph_module(&bytes, binding, deadline)?;
            if is_root {
                root_digest = format!("sha256:{}", hex::encode(digest));
            }
            self.write_reconstructed_graph_redirect_if_needed(
                &source_root,
                &source,
                &requested_url,
                &url,
                &mut stats,
                deadline,
            )?;
            self.write_reconstructed_graph_module(
                &source_root,
                &source,
                &filename,
                &bytes,
                &mut stats,
                deadline,
            )?;
            self.enqueue_reconstructed_graph_imports(
                &url,
                &bytes,
                extension,
                &mut queue,
                &mut queued,
                deadline,
            )?;
            materialized.insert(canonical, digest);
        }
        deadline.check()?;
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

    fn verify_reconstructed_graph_module(
        &self,
        bytes: &[u8],
        binding: GraphIntegrity<'_>,
        deadline: &AcquisitionDeadline,
    ) -> Result<[u8; 32]> {
        verify_graph_module_integrity_before(bytes, binding, deadline)?;
        sha256_digest_raw_before(bytes, deadline)
    }

    fn write_reconstructed_graph_redirect_if_needed(
        &self,
        source_root: &TrustedDir,
        source: &Path,
        requested_url: &Url,
        effective_url: &Url,
        stats: &mut ExtractionStats,
        deadline: &AcquisitionDeadline,
    ) -> Result<()> {
        if requested_url != effective_url {
            self.write_reconstructed_graph_redirect(
                source_root,
                source,
                requested_url,
                effective_url,
                stats,
                deadline,
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
        deadline: &AcquisitionDeadline,
    ) -> Result<()> {
        deadline.check()?;
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
        for chunk in bytes.chunks(64 * 1024) {
            deadline.check()?;
            file.write_all(chunk).map_err(|source_error| Error::Io {
                operation: "write reconstructed Deno module".to_owned(),
                path: output.clone(),
                source: source_error,
            })?;
        }
        deadline.check()
    }

    fn enqueue_reconstructed_graph_imports(
        &self,
        url: &Url,
        bytes: &[u8],
        extension: &str,
        queue: &mut VecDeque<Url>,
        queued: &mut HashSet<String>,
        deadline: &AcquisitionDeadline,
    ) -> Result<()> {
        deadline.check()?;
        resolve_graph_modules_with_sink(url, bytes, extension, |module| {
            enqueue_graph_module(queue, queued, module, self.limits.max_packages)
        })?;
        deadline.check()
    }

    fn write_reconstructed_graph_redirect(
        &self,
        source_root: &TrustedDir,
        source: &Path,
        requested_url: &Url,
        effective_url: &Url,
        stats: &mut ExtractionStats,
        deadline: &AcquisitionDeadline,
    ) -> Result<()> {
        deadline.check()?;
        account_extracted_entry(stats, effective_url.as_str().len() as u64, &self.limits)?;
        write_graph_redirect(source_root, source, requested_url, effective_url, deadline)
    }

    fn cached_graph_effective_url(
        &self,
        cached_root: &TrustedDir,
        cached_source: &Path,
        requested_url: &Url,
        lockfile: Option<&DenoLockfileSnapshot>,
        enforce_host_policy: bool,
        deadline: &AcquisitionDeadline,
    ) -> Result<Url> {
        deadline.check()?;
        let locked_effective = lockfile_redirect_effective_url(
            lockfile,
            requested_url,
            self.limits.max_redirect_hops,
            deadline,
        )?;
        let redirect_name = graph_redirect_filename(requested_url);
        let redirect_path = cached_source.join(&redirect_name);
        let bytes = match cached_root.open_file_no_follow(Path::new(&redirect_name)) {
            Ok(file) => read_bounded_file(
                file,
                &redirect_path,
                8 * 1024,
                "cached Deno metadata bytes",
                deadline,
            )?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if let Some(locked_effective) = locked_effective {
                    return Err(Error::Policy {
                        operation: "cache validation".to_owned(),
                        message: format!(
                            "cached Deno redirect for {requested_url} is missing; the lockfile requires effective URL {locked_effective}"
                        ),
                    });
                }
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
        let Some(locked_effective) = locked_effective else {
            return Err(Error::Policy {
                operation: "cache validation".to_owned(),
                message: format!(
                    "cached Deno redirect from {requested_url} to {effective} is not declared by the lockfile"
                ),
            });
        };
        if effective != locked_effective {
            return Err(Error::Policy {
                operation: "cache validation".to_owned(),
                message: format!(
                    "cached Deno redirect from {requested_url} to {effective} does not match lockfile effective URL {locked_effective}"
                ),
            });
        }
        if enforce_host_policy || effective.origin() != requested_url.origin() {
            self.check_url_policy(&effective, false)?;
        }
        deadline.check()?;
        Ok(effective)
    }
}
