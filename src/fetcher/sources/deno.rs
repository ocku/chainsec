use std::path::Path;

use url::Url;

use crate::{
    error::Result,
    model::{Dependency, FetchMetadata},
};

use crate::fetcher::SourceFetcher;

impl SourceFetcher {
    pub(in crate::fetcher) async fn fetch_deno_package(
        &self,
        dependency: &Dependency,
        url: &Url,
        temporary: &Path,
    ) -> Result<FetchMetadata> {
        if dependency.requirement.starts_with("jsr:") {
            let (source, digest, stats) = self
                .fetch_jsr_package(url, temporary, dependency.integrity.as_deref())
                .await?;
            return self.publish(dependency, url, digest, temporary, &source, stats);
        }
        if matches!(url.scheme(), "http" | "https") && !url.path().ends_with(".tgz") {
            let (source, digest, stats) = self
                .fetch_deno_graph(
                    url,
                    temporary,
                    dependency.integrity.as_deref(),
                    dependency.lockfile.as_deref(),
                )
                .await?;
            return self.publish(dependency, url, digest, temporary, &source, stats);
        }

        self.fetch_standalone_archive(dependency, url, temporary)
            .await
    }
}
