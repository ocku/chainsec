use std::fs;

use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use flate2::{Compression, write::GzEncoder};
use sha2::{Digest, Sha256, Sha512};
use url::Url;

use crate::{
    error::{Error, Result},
    model::{Dependency, Ecosystem, FetchMetadata},
};

use super::storage::lock_entry;

fn acquisition(fetcher: &SourceFetcher, dependency: &Dependency) -> Acquisition {
    fetcher.acquisition(dependency).unwrap()
}

fn destination(fetcher: &SourceFetcher, dependency: &Dependency) -> PathBuf {
    acquisition(fetcher, dependency).destination
}

fn cached(fetcher: &SourceFetcher, dependency: &Dependency) -> Option<FetchMetadata> {
    let acquisition = acquisition(fetcher, dependency);
    match fetcher.cached(dependency, &acquisition).unwrap() {
        CacheLookup::Hit(metadata) => Some(metadata),
        CacheLookup::Miss | CacheLookup::InvalidEntry => None,
    }
}

fn write_deno_module(source: &Path, url: &Url, bytes: &[u8]) {
    fs::create_dir_all(source).unwrap();
    let filename = format!(
        "{}.ts",
        hex::encode(Sha256::digest(url.to_string().as_bytes()))
    );
    fs::write(source.join(filename), bytes).unwrap();
}

#[derive(Clone, Copy)]
enum IntegrityAlgorithm {
    Sha256,
    Sha512,
}

fn fixture_archive() -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    let contents = b"module.exports = 1;\n";
    let mut header = tar::Header::new_gnu();
    header.set_mode(0o644);
    header.set_size(contents.len() as u64);
    header.set_cksum();
    archive
        .append_data(&mut header, "package/index.js", contents.as_slice())
        .unwrap();
    archive.finish().unwrap();
    archive.into_inner().unwrap().finish().unwrap()
}

fn integrity(algorithm: IntegrityAlgorithm, archive: &[u8]) -> String {
    match algorithm {
        IntegrityAlgorithm::Sha256 => {
            format!("sha256:{}", hex::encode(Sha256::digest(archive)))
        }
        IntegrityAlgorithm::Sha512 => {
            format!("sha512-{}", STANDARD.encode(Sha512::digest(archive)))
        }
    }
}

fn cached_fixture() -> (tempfile::TempDir, SourceFetcher, Dependency) {
    cached_fixture_with_integrity(IntegrityAlgorithm::Sha256)
}

fn cached_fixture_with_integrity(
    algorithm: IntegrityAlgorithm,
) -> (tempfile::TempDir, SourceFetcher, Dependency) {
    let cache = tempfile::tempdir().unwrap();
    let fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        super::super::FetchPolicy::default(),
        crate::model::EngineLimits::default(),
    )
    .unwrap();
    let archive = fixture_archive();
    let mut dependency = Dependency::declared(Ecosystem::Npm, "fixture", "1.0.0");
    dependency.resolved_version = Some("1.0.0".to_owned());
    dependency.integrity = Some(integrity(algorithm, &archive));
    dependency.source_url = Some("https://example.test/fixture.tgz".to_owned());

    let temporary = cache.path().join("temporary");
    let source = temporary.join("source/package");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("index.js"), b"module.exports = 1;\n").unwrap();
    write_cached_artifact(&temporary, &archive).unwrap();
    let acquisition = acquisition(&fetcher, &dependency);
    fetcher
        .publish(
            &dependency,
            &acquisition,
            &Url::parse("https://example.test/fixture.tgz").unwrap(),
            format!("sha256:{}", hex::encode(Sha256::digest(&archive))),
            &temporary,
            &source,
        )
        .unwrap();

    let cached = cached(&fetcher, &dependency).unwrap();
    assert!(cached.cache_hit);
    assert!(!cached.source.starts_with(cache.path().join("cache")));
    assert_eq!(
        fs::read(cached.source.join("index.js")).unwrap(),
        b"module.exports = 1;\n"
    );
    (cache, fetcher, dependency)
}

mod identity;
mod publication;
mod purge_lifecycle;
mod restoration;
mod security;
