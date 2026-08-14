use std::path::Path;

use crate::{
    error::Result,
    model::{Dependency, FetchMetadata},
};

use crate::fetcher::{Acquisition, FetchRequest, SourceFetcher, cache::CachePublication};

impl SourceFetcher {
    pub(in crate::fetcher) async fn fetch_deno_package(
        &self,
        dependency: &Dependency,
        acquisition: &Acquisition,
        request: FetchRequest<'_>,
        temporary: &Path,
        budget: &mut crate::fetcher::network::NetworkBudget,
    ) -> Result<FetchMetadata> {
        if dependency.requirement.starts_with("jsr:") {
            let (source, digest, _, effective_metadata_url) = self
                .fetch_jsr_package_with_budget(
                    request.url,
                    temporary,
                    dependency.integrity.as_deref(),
                    budget,
                )
                .await?;
            return self.publish_with_effective_source_url(CachePublication {
                dependency,
                acquisition,
                source_url: request.url,
                effective_source_url: Some(&effective_metadata_url),
                digest,
                temporary,
                source_directory: &source,
            });
        }
        if matches!(request.url.scheme(), "http" | "https") && !request.url.path().ends_with(".tgz")
        {
            let (source, digest, _) = self
                .fetch_deno_graph_with_budget(
                    request.url,
                    temporary,
                    dependency.integrity.as_deref(),
                    acquisition.deno_lockfile.as_ref(),
                    budget,
                )
                .await?;
            return self.publish(
                dependency,
                acquisition,
                request.url,
                digest,
                temporary,
                &source,
            );
        }

        self.fetch_standalone_archive(dependency, acquisition, request, temporary, budget)
            .await
    }
}
