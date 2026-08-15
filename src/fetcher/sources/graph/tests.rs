use base64::Engine as _;

use super::*;
use crate::fetcher::{filesystem::TrustedDir, integrity::sha256_digest_raw_before};
use cache_io::cached_graph_module_filename;
use integrity::{verify_graph_module_integrity_from_digest, verify_materialized_module_bytes};

mod cache;
mod lock_integrity;
mod policy_budgets;
mod queue;
mod redirect_integrity;
mod resolution;

fn integrity(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn sha512_integrity(bytes: &[u8]) -> String {
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(bytes))
    )
}

fn raw_sha256(bytes: &[u8]) -> [u8; 32] {
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&Sha256::digest(bytes));
    digest
}

fn lockfile_snapshot(contents: &str) -> DenoLockfileSnapshot {
    let value = serde_json::from_str(contents).unwrap();
    DenoLockfileSnapshot::from_lockfile(contents.as_bytes(), &value)
}

fn remote_snapshot(remote_integrities: HashMap<String, String>) -> DenoLockfileSnapshot {
    DenoLockfileSnapshot::from_remote_integrities("test", remote_integrities)
}

fn remote_snapshot_with_redirects(
    remote_integrities: HashMap<String, String>,
    redirects: HashMap<String, String>,
) -> DenoLockfileSnapshot {
    DenoLockfileSnapshot::from_remote_integrities_and_redirects(
        "test",
        remote_integrities,
        redirects,
    )
}

fn graph_fetcher() -> (tempfile::TempDir, SourceFetcher) {
    let cache = tempfile::tempdir().unwrap();
    let policy = crate::fetcher::FetchPolicy {
        allowed_hosts: vec!["example.test".to_owned()],
        ..crate::fetcher::FetchPolicy::default()
    };
    let fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        policy,
        crate::model::EngineLimits::default(),
    )
    .unwrap();
    (cache, fetcher)
}

fn write_cached_module(source: &Path, url: &Url, bytes: &[u8]) {
    fs::create_dir_all(source).unwrap();
    let filename = format!(
        "{}.{}",
        hex::encode(Sha256::digest(canonical_graph_url(url).as_bytes())),
        module_extension(url)
    );
    fs::write(source.join(filename), bytes).unwrap();
}
