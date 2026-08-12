use std::path::Path;

use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    error::Result,
    model::{Dependency, FetchMetadata},
};

use crate::fetcher::{
    Acquisition, SourceFetcher,
    archive::{extract, single_root_or_self},
    cache::write_cached_artifact,
    integrity::verify_integrity,
};

impl SourceFetcher {
    pub(in crate::fetcher) async fn fetch_standalone_archive(
        &self,
        dependency: &Dependency,
        acquisition: &Acquisition,
        url: &Url,
        repository_request: bool,
        temporary: &Path,
        budget: &mut crate::fetcher::network::NetworkBudget,
    ) -> Result<FetchMetadata> {
        let bytes = self
            .download_with_budget(url, repository_request, budget)
            .await?;
        verify_integrity(&bytes, dependency.integrity.as_deref(), url.as_str())?;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        write_cached_artifact(temporary, &bytes)?;
        let source = self.create_workspace_subdirectory(
            temporary,
            Path::new("source"),
            "create extraction directory",
        )?;
        extract(&bytes, url.path(), &source, &self.limits)?;
        let package_root = single_root_or_self(&source)?;
        self.publish(
            dependency,
            acquisition,
            url,
            digest,
            temporary,
            &package_root,
        )
    }
}
