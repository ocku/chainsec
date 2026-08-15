use std::path::Path;

use crate::{
    error::Result,
    model::{Dependency, FetchMetadata},
};

use crate::fetcher::{
    Acquisition, FetchRequest, SourceFetcher,
    archive::{extract_before, single_root_or_self_before},
    cache::{CachePublication, write_cached_artifact_before},
    integrity::verify_integrity_digest_before,
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
        let deadline = budget.deadline_guard();
        let digest = verify_integrity_digest_before(
            &bytes,
            dependency.integrity.as_deref(),
            request.url.as_str(),
            &deadline,
        )?;
        write_cached_artifact_before(temporary, &bytes, &deadline)?;
        let source = self.create_workspace_subdirectory(
            temporary,
            Path::new("source"),
            "create extraction directory",
        )?;
        extract_before(&bytes, request.url.path(), &source, &self.limits, &deadline)?;
        let package_root = single_root_or_self_before(&source, &deadline)?;
        self.publish_with_effective_source_url(CachePublication {
            dependency,
            acquisition,
            source_url: request.url,
            effective_source_url: None,
            digest,
            temporary,
            source_directory: &package_root,
            deadline: &deadline,
        })
    }
}
