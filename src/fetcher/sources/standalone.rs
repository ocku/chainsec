use std::path::Path;

use crate::{
    error::Result,
    model::{Dependency, FetchMetadata},
};

use crate::fetcher::{
    Acquisition, FetchRequest, SourceFetcher,
    archive::{extract, single_root_or_self},
    cache::write_cached_artifact,
    integrity::verify_integrity_digest,
};

impl SourceFetcher {
    pub(in crate::fetcher) async fn fetch_standalone_archive(
        &self,
        dependency: &Dependency,
        acquisition: &Acquisition,
        request: FetchRequest<'_>,
        temporary: &Path,
        budget: &mut crate::fetcher::network::NetworkBudget,
    ) -> Result<FetchMetadata> {
        let bytes = match request.source_repository {
            Some(repository_base) => {
                self.download_with_budget_from_repository(request.url, repository_base, budget)
                    .await?
            }
            None => {
                self.download_with_budget(request.url, request.repository_request, budget)
                    .await?
            }
        };
        let digest = verify_integrity_digest(
            &bytes,
            dependency.integrity.as_deref(),
            request.url.as_str(),
        )?;
        write_cached_artifact(temporary, &bytes)?;
        let source = self.create_workspace_subdirectory(
            temporary,
            Path::new("source"),
            "create extraction directory",
        )?;
        extract(&bytes, request.url.path(), &source, &self.limits)?;
        let package_root = single_root_or_self(&source)?;
        self.publish(
            dependency,
            acquisition,
            request.url,
            digest,
            temporary,
            &package_root,
        )
    }
}
