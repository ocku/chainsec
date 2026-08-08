use std::{fs, path::Path};

use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    error::{Error, Result},
    model::{Dependency, FetchMetadata},
};

use crate::fetcher::{
    SourceFetcher,
    archive::{extract, single_root_or_self},
    integrity::verify_integrity,
};

impl SourceFetcher {
    pub(in crate::fetcher) async fn fetch_standalone_archive(
        &self,
        dependency: &Dependency,
        url: &Url,
        temporary: &Path,
    ) -> Result<FetchMetadata> {
        let bytes = self.download(url).await?;
        verify_integrity(&bytes, dependency.integrity.as_deref(), url.as_str())?;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        let source = temporary.join("source");
        fs::create_dir(&source).map_err(|source_error| Error::Io {
            operation: "create extraction directory".to_owned(),
            path: source.clone(),
            source: source_error,
        })?;
        let stats = extract(&bytes, url.path(), &source, &self.limits)?;
        let package_root = single_root_or_self(&source)?;
        self.publish(dependency, url, digest, temporary, &package_root, stats)
    }
}
