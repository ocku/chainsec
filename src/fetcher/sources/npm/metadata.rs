use std::sync::Arc;

use serde_json::Value as JsonValue;

use crate::{
    error::{Error, Result},
    fetcher::SourceFetcher,
    model::Dependency,
};

impl SourceFetcher {
    pub(super) async fn npm_metadata_with_budget(
        &self,
        dependency: &Dependency,
        package: &str,
        budget: &mut crate::fetcher::network::NetworkBudget,
    ) -> Result<Arc<JsonValue>> {
        let api = self.policy.repositories.npm_metadata_url(package)?;
        let key = api.as_str();
        if let Some(metadata) = self.cached_npm_metadata(key).await {
            return Ok(metadata);
        }

        let request_lock = self
            .npm_metadata_locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(key.to_owned())
            .or_default()
            .clone();
        let _request_guard = request_lock.lock().await;
        if let Some(metadata) = self.cached_npm_metadata(key).await {
            return Ok(metadata);
        }

        let (bytes, _) = self
            .download_with_accept_and_budget(
                &api,
                true,
                "application/vnd.npm.install-v1+json",
                budget,
            )
            .await?;
        let metadata =
            Arc::new(
                serde_json::from_slice(&bytes).map_err(|error| Error::Resolution {
                    package: dependency.id(),
                    message: format!("invalid npm registry response: {error}"),
                })?,
            );
        self.cache_npm_metadata(key, &metadata, bytes.len()).await;
        Ok(metadata)
    }
}
