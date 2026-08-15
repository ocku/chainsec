use std::sync::Arc;

use serde_json::Value as JsonValue;

use crate::fetcher::SourceFetcher;

const MAX_CACHED_NPM_METADATA_BYTES: usize = 32 * 1024 * 1024;

impl SourceFetcher {
    pub(super) async fn cached_npm_metadata(&self, key: &str) -> Option<Arc<JsonValue>> {
        self.npm_metadata
            .lock()
            .await
            .documents
            .get(key)
            .map(|(metadata, _)| Arc::clone(metadata))
    }

    pub(super) async fn cache_npm_metadata(
        &self,
        key: &str,
        metadata: &Arc<JsonValue>,
        metadata_bytes: usize,
    ) {
        let mut cache = self.npm_metadata.lock().await;
        while cache.bytes.saturating_add(metadata_bytes) > MAX_CACHED_NPM_METADATA_BYTES
            && !cache.documents.is_empty()
        {
            let evicted = cache.documents.keys().next().cloned().unwrap();
            if let Some((_, bytes)) = cache.documents.remove(&evicted) {
                cache.bytes = cache.bytes.saturating_sub(bytes);
            }
        }
        cache.bytes = cache.bytes.saturating_add(metadata_bytes);
        cache
            .documents
            .insert(key.to_owned(), (Arc::clone(metadata), metadata_bytes));
    }
}
