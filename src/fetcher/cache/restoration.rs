use std::{
    fs,
    path::{Path, PathBuf},
};

use url::Url;

use crate::{
    error::{Error, Result},
    model::{Dependency, Ecosystem, FetchMetadata},
};

use super::{
    CACHED_ARTIFACT, COMPLETION_MARKER, CacheLookup, MAX_COMPLETION_MARKER_BYTES,
    UNVERIFIED_CACHE_SOURCE_URL,
    metadata::CacheMetadata,
    storage::{lock_entry_before, lock_entry_shared_before, read_bounded_regular_file},
};
use crate::fetcher::{
    Acquisition, SourceFetcher,
    archive::{extract_before, single_root_or_self_before},
    budget::AcquisitionDeadline,
    filesystem::TrustedDir,
    integrity::verify_integrity_digest_before,
};

fn cache_restoration_error_is_fatal(error: &Error) -> bool {
    matches!(error, Error::LimitExceeded { .. })
        || matches!(error, Error::Io { source, .. } if source.kind() != std::io::ErrorKind::NotFound)
        || matches!(error, Error::Policy { operation, .. } if operation == "cache confinement")
}

impl SourceFetcher {
    #[cfg(test)]
    pub(in crate::fetcher) fn cached(
        &self,
        dependency: &Dependency,
        acquisition: &Acquisition,
    ) -> Result<CacheLookup<FetchMetadata>> {
        let deadline = self.network_budget().deadline_guard();
        self.cached_before(dependency, acquisition, &deadline)
    }

    pub(in crate::fetcher) fn cached_before(
        &self,
        dependency: &Dependency,
        acquisition: &Acquisition,
        deadline: &AcquisitionDeadline,
    ) -> Result<CacheLookup<FetchMetadata>> {
        deadline.check()?;
        // A GitHub commit pins the codeload request, but it is not a digest of the
        // returned archive or tree. With no independently trusted digest, an
        // untrusted offline cache cannot authenticate a retained GitHub archive.
        if dependency.is_pinned_github() {
            return Ok(CacheLookup::Miss);
        }

        let shared_lock = lock_entry_shared_before(acquisition, deadline)?;
        match self.restore_cached_entry(dependency, acquisition, deadline)? {
            CacheLookup::Hit((metadata, workspace)) => {
                deadline.check()?;
                self.retain_workspace(workspace);
                Ok(CacheLookup::Hit(metadata))
            }
            CacheLookup::Miss => Ok(CacheLookup::Miss),
            CacheLookup::InvalidEntry => {
                drop(shared_lock);
                let _exclusive_lock = lock_entry_before(acquisition, deadline)?;
                match self.restore_cached_entry(dependency, acquisition, deadline)? {
                    CacheLookup::Hit((metadata, workspace)) => {
                        deadline.check()?;
                        self.retain_workspace(workspace);
                        Ok(CacheLookup::Hit(metadata))
                    }
                    CacheLookup::Miss => Ok(CacheLookup::Miss),
                    CacheLookup::InvalidEntry => {
                        deadline.check()?;
                        self.quarantine_invalid_cache_entry(acquisition)?;
                        deadline.check()?;
                        Ok(CacheLookup::InvalidEntry)
                    }
                }
            }
        }
    }

    fn quarantine_invalid_cache_entry(&self, acquisition: &Acquisition) -> Result<()> {
        let quarantine = self.create_cache_staging_directory("invalid-cache-entry")?;
        acquisition
            .ecosystem
            .rename_child(
                Path::new(&acquisition.identity),
                &self.cache_root,
                &quarantine.name,
            )
            .map_err(|source| Error::Io {
                operation: "quarantine invalid cache entry".to_owned(),
                path: acquisition.destination.clone(),
                source,
            })
    }

    pub(super) fn restore_cached_entry(
        &self,
        dependency: &Dependency,
        acquisition: &Acquisition,
        deadline: &AcquisitionDeadline,
    ) -> Result<CacheLookup<(FetchMetadata, PathBuf)>> {
        deadline.check()?;
        let destination = &acquisition.destination;
        let directory = match acquisition
            .ecosystem
            .open_subdirectory(Path::new(&acquisition.identity))
        {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(CacheLookup::Miss);
            }
            Err(error) if super::is_unsafe_cache_open_error(&error) => {
                return Ok(CacheLookup::InvalidEntry);
            }
            Err(source) => {
                return Err(Error::Io {
                    operation: "open cache entry".to_owned(),
                    path: destination.to_owned(),
                    source,
                });
            }
        };
        let Some(marker) = read_bounded_regular_file(
            &directory,
            Path::new(COMPLETION_MARKER),
            &destination.join(COMPLETION_MARKER),
            MAX_COMPLETION_MARKER_BYTES,
            deadline,
        )?
        else {
            return Ok(CacheLookup::InvalidEntry);
        };
        deadline.check()?;
        let Ok(metadata) = serde_json::from_slice::<CacheMetadata>(&marker) else {
            return Ok(CacheLookup::InvalidEntry);
        };
        if !metadata.matches_dependency(dependency) {
            return Ok(CacheLookup::InvalidEntry);
        }
        let Ok(source_url) = Url::parse(&metadata.source_url) else {
            return Ok(CacheLookup::InvalidEntry);
        };
        let effective_source_url = metadata
            .effective_source_url
            .as_deref()
            .map(Url::parse)
            .transpose()
            .ok()
            .flatten();
        if metadata.effective_source_url.is_some() && effective_source_url.is_none() {
            return Ok(CacheLookup::InvalidEntry);
        }

        let temporary = self.create_workspace_directory()?;
        let restored = if dependency.ecosystem == Ecosystem::Deno
            && dependency.requirement.starts_with("jsr:")
        {
            self.restore_cached_jsr(
                dependency,
                effective_source_url.as_ref().unwrap_or(&source_url),
                &directory,
                destination,
                &temporary,
                deadline,
            )
        } else if super::is_deno_graph(dependency) {
            self.restore_cached_deno_graph(
                dependency,
                acquisition,
                &source_url,
                destination,
                &temporary,
                deadline,
            )
        } else {
            self.restore_cached_archive(
                dependency,
                &source_url,
                &directory,
                destination,
                &temporary,
                deadline,
            )
        };

        match restored {
            Ok(metadata) => Ok(CacheLookup::Hit((metadata, temporary))),
            Err(error) => {
                if temporary.exists() && deadline.check().is_ok() {
                    let _ = fs::remove_dir_all(&temporary);
                }
                if cache_restoration_error_is_fatal(&error) {
                    Err(error)
                } else {
                    Ok(CacheLookup::InvalidEntry)
                }
            }
        }
    }

    fn restore_cached_archive(
        &self,
        dependency: &Dependency,
        source_url: &Url,
        directory: &TrustedDir,
        destination: &Path,
        temporary: &Path,
        deadline: &AcquisitionDeadline,
    ) -> Result<FetchMetadata> {
        deadline.check()?;
        let bytes = read_bounded_regular_file(
            directory,
            Path::new(CACHED_ARTIFACT),
            &destination.join(CACHED_ARTIFACT),
            self.limits.max_archive_size,
            deadline,
        )?
        .ok_or_else(|| Error::Policy {
            operation: "cache validation".to_owned(),
            message: "cached archive is missing, unsafe, or exceeds the archive limit".to_owned(),
        })?;
        let digest = verify_integrity_digest_before(
            &bytes,
            dependency.integrity.as_deref(),
            source_url.as_str(),
            deadline,
        )?;

        let source = self.create_workspace_subdirectory(
            temporary,
            Path::new("source"),
            "create cache reconstruction directory",
        )?;
        extract_before(&bytes, source_url.path(), &source, &self.limits, deadline)?;
        let package_root = single_root_or_self_before(&source, deadline)?;
        self.reconstructed_metadata(dependency, source_url, digest, temporary, &package_root)
    }

    fn restore_cached_jsr(
        &self,
        dependency: &Dependency,
        source_url: &Url,
        directory: &TrustedDir,
        destination: &Path,
        temporary: &Path,
        deadline: &AcquisitionDeadline,
    ) -> Result<FetchMetadata> {
        deadline.check()?;
        let metadata_bytes = read_bounded_regular_file(
            directory,
            Path::new(CACHED_ARTIFACT),
            &destination.join(CACHED_ARTIFACT),
            self.limits.max_archive_size,
            deadline,
        )?
        .ok_or_else(|| Error::Policy {
            operation: "cache validation".to_owned(),
            message: "cached JSR manifest is missing, unsafe, or exceeds the archive limit"
                .to_owned(),
        })?;
        let (source, digest, _) = self.rebuild_cached_jsr_package_before(
            source_url,
            temporary,
            dependency.integrity.as_deref(),
            &metadata_bytes,
            &destination.join("source"),
            deadline,
        )?;
        self.reconstructed_metadata(dependency, source_url, digest, temporary, &source)
    }

    fn restore_cached_deno_graph(
        &self,
        dependency: &Dependency,
        acquisition: &Acquisition,
        source_url: &Url,
        destination: &Path,
        temporary: &Path,
        deadline: &AcquisitionDeadline,
    ) -> Result<FetchMetadata> {
        deadline.check()?;
        let (source, digest, _) = self.rebuild_cached_deno_graph_before(
            source_url,
            temporary,
            dependency.integrity.as_deref(),
            acquisition.deno_lockfile.as_ref(),
            &destination.join("source"),
            deadline,
        )?;
        self.reconstructed_metadata(dependency, source_url, digest, temporary, &source)
    }

    fn reconstructed_metadata(
        &self,
        dependency: &Dependency,
        source_url: &Url,
        digest: String,
        temporary: &Path,
        source_directory: &Path,
    ) -> Result<FetchMetadata> {
        let source =
            super::workspace_source_path(dependency, source_url, temporary, source_directory)?;
        let mut metadata =
            CacheMetadata::new(dependency, source_url, digest).into_fetch_metadata(source, true);
        metadata.source_url = dependency
            .source_url
            .clone()
            .or_else(|| super::is_deno_graph(dependency).then(|| dependency.requirement.clone()))
            .unwrap_or_else(|| UNVERIFIED_CACHE_SOURCE_URL.to_owned());
        Ok(metadata)
    }
}
