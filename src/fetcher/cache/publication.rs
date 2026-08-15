use std::path::Path;

use url::Url;

use crate::{
    error::{Error, Result},
    model::{Dependency, Ecosystem, FetchMetadata},
};

use super::{
    COMPLETION_MARKER, CacheLookup, CachePublication,
    metadata::CacheMetadata,
    storage::{copy_cache_payload, lock_entry_before, write_child_file_before},
};
use crate::fetcher::{
    Acquisition, SourceFetcher, budget::AcquisitionDeadline, filesystem::TrustedDir,
};

fn write_completion_marker(
    directory: &TrustedDir,
    destination: &Path,
    metadata: &CacheMetadata,
    dependency: &Dependency,
    source_url: &Url,
    deadline: &AcquisitionDeadline,
) -> Result<()> {
    let encoded = serde_json::to_vec_pretty(metadata).map_err(|error| Error::Fetch {
        package: dependency.id(),
        source_url: source_url.to_string(),
        message: error.to_string(),
    })?;
    write_child_file_before(
        directory,
        Path::new(COMPLETION_MARKER),
        &destination.join(COMPLETION_MARKER),
        &encoded,
        "cache completion marker",
        deadline,
    )
}

impl SourceFetcher {
    fn publish_cache_entry(
        &self,
        publication: &super::super::CacheStaging,
        dependency: &Dependency,
        acquisition: &Acquisition,
        deadline: &AcquisitionDeadline,
    ) -> Result<()> {
        deadline.check()?;
        let destination = &acquisition.destination;
        match self.restore_cached_entry(dependency, acquisition, deadline)? {
            CacheLookup::Hit((_, _validation_workspace)) => {
                // Both workspaces remain confined and are reclaimed by the fetcher or cache
                // purge. Avoid an uninterruptible recursive cleanup in the acquisition path.
                deadline.check()?;
                return Ok(());
            }
            CacheLookup::Miss => {}
            CacheLookup::InvalidEntry => {
                let quarantine = self.create_cache_staging_directory("invalid-cache-entry")?;
                deadline.check()?;
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
                if let Err(error) = deadline.check() {
                    let _ = self.cache_root.rename_child(
                        &quarantine.name,
                        &acquisition.ecosystem,
                        Path::new(&acquisition.identity),
                    );
                    return Err(error);
                }
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
                deadline.check()?;
                return Ok(());
            }
        }

        deadline.check()?;
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
            })?;
        deadline.check()
    }

    #[cfg(test)]
    pub(in crate::fetcher) fn complete_without_cache(
        &self,
        dependency: &Dependency,
        source_url: &Url,
        digest: String,
        temporary: &Path,
        source_directory: &Path,
    ) -> Result<FetchMetadata> {
        let deadline = self.network_budget().deadline_guard();
        self.complete_without_cache_before(
            dependency,
            source_url,
            digest,
            temporary,
            source_directory,
            &deadline,
        )
    }

    pub(in crate::fetcher) fn complete_without_cache_before(
        &self,
        dependency: &Dependency,
        source_url: &Url,
        digest: String,
        temporary: &Path,
        source_directory: &Path,
        deadline: &AcquisitionDeadline,
    ) -> Result<FetchMetadata> {
        deadline.check()?;
        let source =
            super::workspace_source_path(dependency, source_url, temporary, source_directory)?;
        let metadata = CacheMetadata::new(dependency, source_url, digest);
        deadline.check()?;
        self.retain_workspace(temporary.to_owned());
        Ok(metadata.into_fetch_metadata(source, false))
    }

    #[cfg(test)]
    pub(in crate::fetcher) fn publish(
        &self,
        dependency: &Dependency,
        acquisition: &Acquisition,
        source_url: &Url,
        digest: String,
        temporary: &Path,
        source_directory: &Path,
    ) -> Result<FetchMetadata> {
        let deadline = self.network_budget().deadline_guard();
        self.publish_with_effective_source_url(CachePublication {
            dependency,
            acquisition,
            source_url,
            effective_source_url: None,
            digest,
            temporary,
            source_directory,
            deadline: &deadline,
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
            deadline,
        } = publication;
        deadline.check()?;
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
                deadline,
            )?;
            write_completion_marker(
                &publication.directory,
                &publication.path,
                &metadata,
                dependency,
                source_url,
                deadline,
            )?;
            let _lock = lock_entry_before(acquisition, deadline)?;
            self.publish_cache_entry(&publication, dependency, acquisition, deadline)
        })();
        if publication_result.is_err() && deadline.check().is_ok() {
            let _ = self.cache_root.remove_child_all(&publication.name);
        }
        publication_result?;

        deadline.check()?;
        self.retain_workspace(temporary.to_owned());
        Ok(metadata.into_fetch_metadata(source, false))
    }
}
