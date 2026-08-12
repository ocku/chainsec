use std::path::Path;

use sha2::{Digest, Sha256};

use crate::{
    error::Result,
    model::{Dependency, FetchMetadata},
};

use crate::fetcher::{
    SourceFetcher,
    archive::{extract, single_root_or_self},
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
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        let source = self.create_workspace_subdirectory(
            temporary,
            Path::new("source"),
            "create extraction directory",
        )?;
        extract(&bytes, "git.tar.gz", &source, &self.limits)?;
        let package_root = single_root_or_self(&source)?;
        self.complete_without_cache(dependency, &url, digest, temporary, &package_root)
    }
}
