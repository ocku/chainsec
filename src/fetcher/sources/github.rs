use std::path::Path;

use crate::{
    error::Result,
    model::{Dependency, FetchMetadata},
};

use crate::fetcher::{
    SourceFetcher,
    archive::{extract_before, single_root_or_self_before},
    integrity::sha256_digest_before,
};

impl SourceFetcher {
    pub(in crate::fetcher) async fn fetch_github_archive(
        &self,
        dependency: &Dependency,
        temporary: &Path,
        budget: &mut crate::fetcher::network::NetworkBudget,
    ) -> Result<FetchMetadata> {
        let url = dependency
            .github_archive_url()
            .expect("GitHub archive fetch requires a validated GitHub commit pin");
        let bytes = self.download_with_budget(&url, false, budget).await?;
        let deadline = budget.deadline_guard();
        let digest = sha256_digest_before(&bytes, &deadline)?;
        let source = self.create_workspace_subdirectory(
            temporary,
            Path::new("source"),
            "create extraction directory",
        )?;
        extract_before(&bytes, "git.tar.gz", &source, &self.limits, &deadline)?;
        let package_root = single_root_or_self_before(&source, &deadline)?;
        self.complete_without_cache_before(
            dependency,
            &url,
            digest,
            temporary,
            &package_root,
            &deadline,
        )
    }
}
