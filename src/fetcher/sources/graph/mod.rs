use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::Write,
    path::{Path, PathBuf},
};

#[cfg(test)]
use std::fs;

use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    error::{Error, Result},
    model::DenoLockfileSnapshot,
};

use crate::fetcher::{
    SourceFetcher,
    archive::{ExtractionStats, account_extracted_entry},
    budget::AcquisitionDeadline,
    filesystem::TrustedDir,
    integrity::sha256_digest_raw_before,
};

mod cache;
mod cache_io;
mod integrity;
mod resolution;
#[cfg(test)]
mod tests;

#[cfg(test)]
use cache_io::read_cached_graph_module;
#[cfg(test)]
use integrity::verify_graph_module_integrity;
use integrity::{
    GraphIntegrity, verify_graph_module_integrity_before,
    verify_graph_module_integrity_from_digest_before, verify_materialized_module_bytes,
};
#[cfg(test)]
use resolution::resolve_graph_modules;
use resolution::{module_extension, resolve_graph_modules_with_sink};

impl SourceFetcher {
    pub(in crate::fetcher) async fn fetch_deno_graph_with_budget(
        &self,
        root_url: &Url,
        temporary: &Path,
        expected: Option<&str>,
        lockfile: Option<&DenoLockfileSnapshot>,
        budget: &mut crate::fetcher::network::NetworkBudget,
    ) -> Result<(PathBuf, String, ExtractionStats)> {
        let deadline = budget.deadline_guard();
        deadline.check()?;
        let remote_integrities = lockfile.map(DenoLockfileSnapshot::remote_integrities);
        let source = self.create_workspace_subdirectory(
            temporary,
            Path::new("source"),
            "create Deno graph directory",
        )?;
        let source_root = TrustedDir::open(&source).map_err(|source_error| Error::Io {
            operation: "open Deno graph directory".to_owned(),
            path: source.clone(),
            source: source_error,
        })?;
        let mut queue = VecDeque::from([root_url.clone()]);
        let mut queued = HashSet::from([canonical_graph_url(root_url)]);
        let mut materialized = HashMap::<String, [u8; 32]>::new();
        let mut stats = ExtractionStats::default();
        let mut root_digest = String::new();
        while let Some(requested_url) = queue.pop_front() {
            deadline.check()?;
            let is_root = requested_url == *root_url;
            let (downloaded_bytes, url) = self
                .download_with_effective_url_and_budget(&requested_url, false, budget)
                .await?;
            let canonical = canonical_graph_url(&url);
            let binding = GraphIntegrity {
                requested_url: &requested_url,
                effective_url: &url,
                is_root,
                root_url,
                expected,
                remote_integrities,
            };
            if let Some(stored_digest) = materialized.get(&canonical) {
                match verify_graph_module_integrity_from_digest_before(
                    stored_digest,
                    binding,
                    &deadline,
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
                            &deadline,
                        )?;
                    }
                }
                if is_root {
                    root_digest = format!("sha256:{}", hex::encode(stored_digest));
                }
                if requested_url != url {
                    account_extracted_entry(&mut stats, url.as_str().len() as u64, &self.limits)?;
                    write_graph_redirect(&source_root, &source, &requested_url, &url, &deadline)?;
                }
                continue;
            }
            let digest = verify_downloaded_graph_module(&downloaded_bytes, binding, &deadline)?;
            if is_root {
                root_digest = format!("sha256:{}", hex::encode(digest));
            }
            if requested_url != url {
                // Live redirects remain policy-checked network observations. This preserves
                // compatibility with older lockfiles whose integrity entries bind only the
                // requested or effective URL and which have no authenticated redirect table.
                // The persisted metadata is never authority by itself: cache reconstruction
                // requires the exact final target to be declared by a v5 lockfile redirect;
                // otherwise the cache entry is rejected and must be re-established online.
                account_extracted_entry(&mut stats, url.as_str().len() as u64, &self.limits)?;
                write_graph_redirect(&source_root, &source, &requested_url, &url, &deadline)?;
            }
            check_graph_module_limit(materialized.len(), self.limits.max_packages)?;
            account_extracted_entry(&mut stats, downloaded_bytes.len() as u64, &self.limits)?;
            materialize_graph_module(
                &source_root,
                &source,
                &url,
                &canonical,
                &downloaded_bytes,
                &mut queue,
                &mut queued,
                self.limits.max_packages,
                &deadline,
            )?;
            materialized.insert(canonical, digest);
        }
        deadline.check()?;
        Ok((source, root_digest, stats))
    }
}

fn verify_downloaded_graph_module(
    bytes: &[u8],
    binding: GraphIntegrity<'_>,
    deadline: &AcquisitionDeadline,
) -> Result<[u8; 32]> {
    let digest = sha256_digest_raw_before(bytes, deadline)?;
    verify_graph_module_integrity_before(bytes, binding, deadline)?;
    Ok(digest)
}

fn check_graph_module_limit(materialized: usize, max_modules: usize) -> Result<()> {
    if materialized >= max_modules {
        return Err(Error::LimitExceeded {
            resource: "Deno graph modules".to_owned(),
            limit: max_modules as u64,
        });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn materialize_graph_module(
    source_root: &TrustedDir,
    source: &Path,
    url: &Url,
    canonical: &str,
    bytes: &[u8],
    queue: &mut VecDeque<Url>,
    queued: &mut HashSet<String>,
    max_modules: usize,
    deadline: &AcquisitionDeadline,
) -> Result<()> {
    deadline.check()?;
    let extension = module_extension(url);
    let filename = format!(
        "{}.{}",
        hex::encode(Sha256::digest(canonical.as_bytes())),
        extension
    );
    write_graph_module(source_root, source, &filename, bytes, deadline)?;
    resolve_graph_modules_with_sink(url, bytes, extension, |module| {
        enqueue_graph_module(queue, queued, module, max_modules)
    })?;
    deadline.check()
}

fn write_graph_module(
    source_root: &TrustedDir,
    source: &Path,
    filename: &str,
    bytes: &[u8],
    deadline: &AcquisitionDeadline,
) -> Result<()> {
    deadline.check()?;
    let output = source.join(filename);
    let mut file = source_root
        .create_new_file(Path::new(filename))
        .map_err(|source_error| Error::Io {
            operation: "create Deno module".to_owned(),
            path: output.clone(),
            source: source_error,
        })?;
    for chunk in bytes.chunks(64 * 1024) {
        deadline.check()?;
        file.write_all(chunk).map_err(|source_error| Error::Io {
            operation: "write Deno module".to_owned(),
            path: output.clone(),
            source: source_error,
        })?;
    }
    deadline.check()
}

fn canonical_graph_url(url: &Url) -> String {
    url.to_string()
}

pub(super) fn enqueue_graph_module(
    queue: &mut VecDeque<Url>,
    queued: &mut HashSet<String>,
    module: Url,
    max_modules: usize,
) -> Result<()> {
    let canonical = canonical_graph_url(&module);
    if queued.contains(&canonical) {
        return Ok(());
    }
    if queued.len() >= max_modules {
        return Err(Error::LimitExceeded {
            resource: "Deno graph modules".to_owned(),
            limit: max_modules as u64,
        });
    }
    queued.insert(canonical);
    queue.push_back(module);
    Ok(())
}

#[cfg(test)]
fn enqueue_graph_modules(
    queue: &mut VecDeque<Url>,
    queued: &mut HashSet<String>,
    modules: Vec<Url>,
) {
    for module in modules {
        let canonical = canonical_graph_url(&module);
        if queued.insert(canonical) {
            queue.push_back(module);
        }
    }
}

fn graph_redirect_filename(requested_url: &Url) -> String {
    format!(
        "{}.redirect",
        hex::encode(Sha256::digest(
            canonical_graph_url(requested_url).as_bytes()
        ))
    )
}

fn write_graph_redirect(
    source_root: &TrustedDir,
    source: &Path,
    requested_url: &Url,
    effective_url: &Url,
    deadline: &AcquisitionDeadline,
) -> Result<()> {
    deadline.check()?;
    let filename = graph_redirect_filename(requested_url);
    let path = source.join(&filename);
    let mut file = source_root
        .create_new_file(Path::new(&filename))
        .map_err(|source_error| Error::Io {
            operation: "create Deno redirect metadata".to_owned(),
            path: path.clone(),
            source: source_error,
        })?;
    file.write_all(effective_url.as_str().as_bytes())
        .map_err(|source_error| Error::Io {
            operation: "write Deno redirect metadata".to_owned(),
            path,
            source: source_error,
        })?;
    deadline.check()
}
