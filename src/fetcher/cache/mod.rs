mod metadata;
mod storage;

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    error::{Error, Result},
    model::{Dependency, Ecosystem, FetchMetadata},
};

use super::{
    Acquisition, SourceFetcher,
    archive::{extract, single_root_or_self},
    filesystem::TrustedDir,
    integrity::verify_integrity,
};

use self::{
    metadata::CacheMetadata,
    storage::{
        copy_cache_payload, lock_entry, lock_entry_shared, read_bounded_regular_file,
        validate_cache_directory, write_child_file,
    },
};

pub(super) use storage::{CacheLock, prepare_cache, purge_cache};
pub(in crate::fetcher) use storage::{is_unsafe_cache_open_error, write_cached_artifact};

const CACHED_ARTIFACT: &str = ".artifact";
const COMPLETION_MARKER: &str = ".complete.json";
const MAX_COMPLETION_MARKER_BYTES: u64 = 64 * 1024;
const UNVERIFIED_CACHE_SOURCE_URL: &str = "cache:integrity-verified-artifact";

pub(super) enum CacheLookup<T> {
    Hit(T),
    Miss,
    InvalidEntry,
}

pub(in crate::fetcher) struct CachePublication<'a> {
    pub(in crate::fetcher) dependency: &'a Dependency,
    pub(in crate::fetcher) acquisition: &'a Acquisition,
    pub(in crate::fetcher) source_url: &'a Url,
    pub(in crate::fetcher) effective_source_url: Option<&'a Url>,
    pub(in crate::fetcher) digest: String,
    pub(in crate::fetcher) temporary: &'a Path,
    pub(in crate::fetcher) source_directory: &'a Path,
}

fn cache_restoration_error_is_fatal(error: &Error) -> bool {
    matches!(error, Error::Io { source, .. } if source.kind() != std::io::ErrorKind::NotFound)
        || matches!(error, Error::Policy { operation, .. } if operation == "cache confinement")
}

fn is_deno_graph(dependency: &Dependency) -> bool {
    dependency.ecosystem == Ecosystem::Deno
        && dependency.requirement.starts_with("http")
        && Url::parse(&dependency.requirement)
            .ok()
            .is_some_and(|url| !url.path().ends_with(".tgz"))
}

fn workspace_source_path(
    dependency: &Dependency,
    source_url: &Url,
    temporary: &Path,
    source_directory: &Path,
) -> Result<PathBuf> {
    source_directory
        .strip_prefix(temporary)
        .map(|relative| temporary.join(relative))
        .map_err(|error| Error::Fetch {
            package: dependency.id(),
            source_url: source_url.to_string(),
            message: error.to_string(),
        })
}

fn write_completion_marker(
    directory: &TrustedDir,
    destination: &Path,
    metadata: &CacheMetadata,
    dependency: &Dependency,
    source_url: &Url,
) -> Result<()> {
    let encoded = serde_json::to_vec_pretty(metadata).map_err(|error| Error::Fetch {
        package: dependency.id(),
        source_url: source_url.to_string(),
        message: error.to_string(),
    })?;
    write_child_file(
        directory,
        Path::new(COMPLETION_MARKER),
        &destination.join(COMPLETION_MARKER),
        &encoded,
        "cache completion marker",
    )
}

impl SourceFetcher {
    pub(super) fn acquisition(&self, dependency: &Dependency) -> Result<Acquisition> {
        let deno_lockfile = (dependency.ecosystem == Ecosystem::Deno
            && dependency.requirement.starts_with("http"))
        .then(|| dependency.deno_lockfile_snapshot.clone())
        .flatten();
        let mut identity = dependency.id().into_bytes();
        if let Some(source_url) = &dependency.source_url {
            identity.extend_from_slice(b"\0source-url\0");
            identity.extend_from_slice(source_url.as_bytes());
        }
        if let Some(lockfile) = &deno_lockfile {
            identity.extend_from_slice(b"\0deno-lockfile\0");
            identity.extend_from_slice(lockfile.identity().as_bytes());
        }
        let key = hex::encode(Sha256::digest(identity));
        let ecosystem_name = dependency.ecosystem.to_string();
        let ecosystem_path = self.cache.join(&ecosystem_name);
        let ecosystem = self
            .cache_root
            .open_or_create_child_dir(Path::new(&ecosystem_name))
            .map_err(|source| {
                if is_unsafe_cache_open_error(&source) {
                    Error::Policy {
                        operation: "cache confinement".to_owned(),
                        message: format!(
                            "cache ecosystem is not a regular directory: {}",
                            ecosystem_path.display()
                        ),
                    }
                } else {
                    Error::Io {
                        operation: "create ecosystem cache".to_owned(),
                        path: ecosystem_path.clone(),
                        source,
                    }
                }
            })?;
        validate_cache_directory(&ecosystem, &ecosystem_path, "cache ecosystem directory")?;
        Ok(Acquisition {
            destination: ecosystem_path.join(&key),
            ecosystem: Arc::new(ecosystem),
            locks: self.cache_locks.clone(),
            lock_directory: self.cache_lock_directory.clone(),
            identity: key,
            deno_lockfile,
        })
    }

    pub(super) fn cached(
        &self,
        dependency: &Dependency,
        acquisition: &Acquisition,
    ) -> Result<CacheLookup<FetchMetadata>> {
        // A GitHub commit pins the codeload request, but it is not a digest of the
        // returned archive or tree. With no independently trusted digest, an
        // untrusted offline cache cannot authenticate a retained GitHub archive.
        if dependency.is_pinned_github() {
            return Ok(CacheLookup::Miss);
        }

        let shared_lock = lock_entry_shared(acquisition)?;
        match self.restore_cached_entry(dependency, acquisition)? {
            CacheLookup::Hit((metadata, workspace)) => {
                self.retain_workspace(workspace);
                Ok(CacheLookup::Hit(metadata))
            }
            CacheLookup::Miss => Ok(CacheLookup::Miss),
            CacheLookup::InvalidEntry => {
                drop(shared_lock);
                let _exclusive_lock = lock_entry(acquisition)?;
                match self.restore_cached_entry(dependency, acquisition)? {
                    CacheLookup::Hit((metadata, workspace)) => {
                        self.retain_workspace(workspace);
                        Ok(CacheLookup::Hit(metadata))
                    }
                    CacheLookup::Miss => Ok(CacheLookup::Miss),
                    CacheLookup::InvalidEntry => {
                        self.remove_invalid_cache_entry(acquisition)?;
                        Ok(CacheLookup::InvalidEntry)
                    }
                }
            }
        }
    }

    fn remove_invalid_cache_entry(&self, acquisition: &Acquisition) -> Result<()> {
        match acquisition
            .ecosystem
            .remove_child_all(Path::new(&acquisition.identity))
        {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(Error::Io {
                operation: "remove invalid cache entry".to_owned(),
                path: acquisition.destination.clone(),
                source,
            }),
        }
    }

    fn restore_cached_entry(
        &self,
        dependency: &Dependency,
        acquisition: &Acquisition,
    ) -> Result<CacheLookup<(FetchMetadata, PathBuf)>> {
        let destination = &acquisition.destination;
        let directory = match acquisition
            .ecosystem
            .open_subdirectory(Path::new(&acquisition.identity))
        {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(CacheLookup::Miss);
            }
            Err(error) if is_unsafe_cache_open_error(&error) => {
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
        )?
        else {
            return Ok(CacheLookup::InvalidEntry);
        };
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
            )
        } else if is_deno_graph(dependency) {
            self.restore_cached_deno_graph(
                dependency,
                acquisition,
                &source_url,
                destination,
                &temporary,
            )
        } else {
            self.restore_cached_archive(
                dependency,
                &source_url,
                &directory,
                destination,
                &temporary,
            )
        };

        match restored {
            Ok(metadata) => Ok(CacheLookup::Hit((metadata, temporary))),
            Err(error) => {
                if temporary.exists() {
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
    ) -> Result<FetchMetadata> {
        let bytes = read_bounded_regular_file(
            directory,
            Path::new(CACHED_ARTIFACT),
            &destination.join(CACHED_ARTIFACT),
            self.limits.max_archive_bytes,
        )?
        .ok_or_else(|| Error::Policy {
            operation: "cache validation".to_owned(),
            message: "cached archive is missing, unsafe, or exceeds the archive limit".to_owned(),
        })?;
        verify_integrity(&bytes, dependency.integrity.as_deref(), source_url.as_str())?;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        write_cached_artifact(temporary, &bytes)?;

        let source = self.create_workspace_subdirectory(
            temporary,
            Path::new("source"),
            "create cache reconstruction directory",
        )?;
        extract(&bytes, source_url.path(), &source, &self.limits)?;
        let package_root = single_root_or_self(&source)?;
        self.reconstructed_metadata(dependency, source_url, digest, temporary, &package_root)
    }

    fn restore_cached_jsr(
        &self,
        dependency: &Dependency,
        source_url: &Url,
        directory: &TrustedDir,
        destination: &Path,
        temporary: &Path,
    ) -> Result<FetchMetadata> {
        let metadata_bytes = read_bounded_regular_file(
            directory,
            Path::new(CACHED_ARTIFACT),
            &destination.join(CACHED_ARTIFACT),
            self.limits.max_archive_bytes,
        )?
        .ok_or_else(|| Error::Policy {
            operation: "cache validation".to_owned(),
            message: "cached JSR manifest is missing, unsafe, or exceeds the archive limit"
                .to_owned(),
        })?;
        let (source, digest, _) = self.rebuild_cached_jsr_package(
            source_url,
            temporary,
            dependency.integrity.as_deref(),
            &metadata_bytes,
            &destination.join("source"),
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
    ) -> Result<FetchMetadata> {
        let (source, digest, _) = self.rebuild_cached_deno_graph(
            source_url,
            temporary,
            dependency.integrity.as_deref(),
            acquisition.deno_lockfile.as_ref(),
            &destination.join("source"),
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
        let source = workspace_source_path(dependency, source_url, temporary, source_directory)?;
        let mut metadata =
            CacheMetadata::new(dependency, source_url, digest).into_fetch_metadata(source, true);
        metadata.source_url = dependency
            .source_url
            .clone()
            .or_else(|| is_deno_graph(dependency).then(|| dependency.requirement.clone()))
            .unwrap_or_else(|| UNVERIFIED_CACHE_SOURCE_URL.to_owned());
        Ok(metadata)
    }

    fn publish_cache_entry(
        &self,
        publication: &super::CacheStaging,
        dependency: &Dependency,
        acquisition: &Acquisition,
    ) -> Result<()> {
        let destination = &acquisition.destination;
        match self.restore_cached_entry(dependency, acquisition)? {
            CacheLookup::Hit((_, validation_workspace)) => {
                let _ = fs::remove_dir_all(&validation_workspace);
                self.cache_root
                    .remove_child_all(&publication.name)
                    .map_err(|source| Error::Io {
                        operation: "discard cache publication after another publisher won"
                            .to_owned(),
                        path: publication.path.clone(),
                        source,
                    })?;
                return Ok(());
            }
            CacheLookup::Miss => {}
            CacheLookup::InvalidEntry => {
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
                        path: destination.to_owned(),
                        source,
                    })?;
                if let Err(source) = self.cache_root.rename_child(
                    &publication.name,
                    &acquisition.ecosystem,
                    Path::new(&acquisition.identity),
                ) {
                    let _ = self.cache_root.rename_child(
                        &quarantine.name,
                        &acquisition.ecosystem,
                        Path::new(&acquisition.identity),
                    );
                    return Err(Error::Io {
                        operation: "replace invalid cache entry".to_owned(),
                        path: destination.to_owned(),
                        source,
                    });
                }
                let _ = self.cache_root.remove_child_all(&quarantine.name);
                return Ok(());
            }
        }

        self.cache_root
            .rename_child(
                &publication.name,
                &acquisition.ecosystem,
                Path::new(&acquisition.identity),
            )
            .map_err(|source| Error::Io {
                operation: "publish cache entry".to_owned(),
                path: destination.to_owned(),
                source,
            })
    }

    pub(super) fn complete_without_cache(
        &self,
        dependency: &Dependency,
        source_url: &Url,
        digest: String,
        temporary: &Path,
        source_directory: &Path,
    ) -> Result<FetchMetadata> {
        let source = workspace_source_path(dependency, source_url, temporary, source_directory)?;
        let metadata = CacheMetadata::new(dependency, source_url, digest);
        self.retain_workspace(temporary.to_owned());
        Ok(metadata.into_fetch_metadata(source, false))
    }

    pub(super) fn publish(
        &self,
        dependency: &Dependency,
        acquisition: &Acquisition,
        source_url: &Url,
        digest: String,
        temporary: &Path,
        source_directory: &Path,
    ) -> Result<FetchMetadata> {
        self.publish_with_effective_source_url(CachePublication {
            dependency,
            acquisition,
            source_url,
            effective_source_url: None,
            digest,
            temporary,
            source_directory,
        })
    }

    pub(super) fn publish_with_effective_source_url(
        &self,
        publication: CachePublication<'_>,
    ) -> Result<FetchMetadata> {
        let CachePublication {
            dependency,
            acquisition,
            source_url,
            effective_source_url,
            digest,
            temporary,
            source_directory,
        } = publication;
        let source = workspace_source_path(dependency, source_url, temporary, source_directory)?;
        let metadata = CacheMetadata::new(dependency, source_url, digest)
            .with_effective_source_url(effective_source_url);
        let retain_source = dependency.ecosystem == Ecosystem::Deno
            && (dependency.requirement.starts_with("jsr:") || is_deno_graph(dependency));

        let publication = self.create_cache_staging_directory("tmp")?;
        let publication_result = (|| {
            copy_cache_payload(
                temporary,
                &publication.directory,
                &publication.path,
                retain_source,
                &self.limits,
            )?;
            write_completion_marker(
                &publication.directory,
                &publication.path,
                &metadata,
                dependency,
                source_url,
            )?;
            let _lock = lock_entry(acquisition)?;
            self.publish_cache_entry(&publication, dependency, acquisition)
        })();
        if publication_result.is_err() {
            let _ = self.cache_root.remove_child_all(&publication.name);
        }
        publication_result?;

        self.retain_workspace(temporary.to_owned());
        Ok(metadata.into_fetch_metadata(source, false))
    }
}

#[cfg(test)]
mod tests;
