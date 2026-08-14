use std::path::Path;

use url::Url;

use crate::{
    error::{Error, Result},
    model::{Dependency, Ecosystem, FetchMetadata},
};

use super::{
    COMPLETION_MARKER, CacheLookup, CachePublication,
    metadata::CacheMetadata,
    storage::{copy_cache_payload, lock_entry, write_child_file},
};
use crate::fetcher::{Acquisition, SourceFetcher, filesystem::TrustedDir};

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
    fn publish_cache_entry(
        &self,
        publication: &super::super::CacheStaging,
        dependency: &Dependency,
        acquisition: &Acquisition,
    ) -> Result<()> {
        let destination = &acquisition.destination;
        match self.restore_cached_entry(dependency, acquisition)? {
            CacheLookup::Hit((_, validation_workspace)) => {
                let _ = std::fs::remove_dir_all(&validation_workspace);
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

    pub(in crate::fetcher) fn complete_without_cache(
        &self,
        dependency: &Dependency,
        source_url: &Url,
        digest: String,
        temporary: &Path,
        source_directory: &Path,
    ) -> Result<FetchMetadata> {
        let source =
            super::workspace_source_path(dependency, source_url, temporary, source_directory)?;
        let metadata = CacheMetadata::new(dependency, source_url, digest);
        self.retain_workspace(temporary.to_owned());
        Ok(metadata.into_fetch_metadata(source, false))
    }

    pub(in crate::fetcher) fn publish(
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

    pub(in crate::fetcher) fn publish_with_effective_source_url(
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
        let source =
            super::workspace_source_path(dependency, source_url, temporary, source_directory)?;
        let metadata = CacheMetadata::new(dependency, source_url, digest)
            .with_effective_source_url(effective_source_url);
        let retain_source = dependency.ecosystem == Ecosystem::Deno
            && (dependency.requirement.starts_with("jsr:") || super::is_deno_graph(dependency));

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
