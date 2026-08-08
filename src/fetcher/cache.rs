use std::{
    fs,
    path::{Component, Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    error::{Error, Result},
    model::{Dependency, Ecosystem, FetchMetadata},
};

use super::{SourceFetcher, archive::ExtractionStats, integrity::hash_tree};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheMetadata {
    package_id: String,
    resolved_version: String,
    integrity: Option<String>,
    digest: String,
    source_url: String,
    source_directory: String,
    extracted_files: u64,
    extracted_bytes: u64,
    content_digest: String,
    fetcher_version: String,
}

impl CacheMetadata {
    fn matches_dependency(&self, fetcher: &SourceFetcher, dependency: &Dependency) -> bool {
        self.matches_identity(dependency)
            && self.matches_source(dependency)
            && self.matches_integrity(dependency)
            && self.matches_extraction_limits(fetcher, dependency)
    }

    fn matches_identity(&self, dependency: &Dependency) -> bool {
        let expected_version = dependency
            .resolved_version
            .as_deref()
            .unwrap_or(&dependency.requirement);

        self.package_id == dependency.id()
            && self.resolved_version == expected_version
            && self.integrity.as_deref() == dependency.integrity.as_deref()
            && self.fetcher_version == env!("CARGO_PKG_VERSION")
    }

    fn matches_source(&self, dependency: &Dependency) -> bool {
        valid_source_url(&self.source_url)
            && dependency
                .source_url
                .as_deref()
                .is_none_or(|source_url| source_url == self.source_url)
    }

    fn matches_integrity(&self, dependency: &Dependency) -> bool {
        !self.digest.is_empty()
            && integrity_matches_digest(dependency.integrity.as_deref(), &self.digest)
            && !self.content_digest.is_empty()
    }

    fn matches_extraction_limits(&self, fetcher: &SourceFetcher, dependency: &Dependency) -> bool {
        self.extracted_files <= fetcher.limits.max_extracted_files
            && self.extracted_bytes <= fetcher.limits.max_extracted_bytes
            && (dependency.ecosystem != Ecosystem::Deno
                || dependency.requirement.starts_with("jsr:")
                || self.extracted_files <= fetcher.policy.max_deno_modules as u64)
    }

    fn source_path(&self, destination: &Path) -> Option<PathBuf> {
        let source_directory = Path::new(&self.source_directory);
        if source_directory.is_absolute()
            || source_directory
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return None;
        }

        let source = destination.join(source_directory);
        if is_symlink(destination)? || is_symlink(&source)? {
            return None;
        }

        let destination = fs::canonicalize(destination).ok()?;
        let source = fs::canonicalize(source).ok()?;
        (source.starts_with(&destination) && source.is_dir()).then_some(source)
    }

    fn new(
        dependency: &Dependency,
        source_url: &Url,
        digest: String,
        source_directory: &Path,
        stats: ExtractionStats,
        content_digest: String,
    ) -> Self {
        Self {
            package_id: dependency.id(),
            resolved_version: dependency
                .resolved_version
                .clone()
                .unwrap_or_else(|| dependency.requirement.clone()),
            integrity: dependency.integrity.clone(),
            digest,
            source_url: source_url.to_string(),
            source_directory: source_directory.to_string_lossy().into_owned(),
            extracted_files: stats.files,
            extracted_bytes: stats.bytes,
            content_digest,
            fetcher_version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    fn into_fetch_metadata(self, source: PathBuf, cache_hit: bool) -> FetchMetadata {
        FetchMetadata {
            source,
            package_id: self.package_id,
            resolved_version: self.resolved_version,
            digest: self.digest,
            source_url: self.source_url,
            cache_hit,
        }
    }
}

fn valid_source_url(source_url: &str) -> bool {
    !source_url.is_empty()
        && Url::parse(source_url)
            .ok()
            .is_some_and(|url| matches!(url.scheme(), "http" | "https"))
}

fn integrity_matches_digest(integrity: Option<&str>, digest: &str) -> bool {
    let Some(integrity) = integrity else {
        return true;
    };
    let Some(hex_digest) = digest.strip_prefix("sha256:") else {
        return false;
    };
    if integrity
        .strip_prefix("sha256:")
        .or_else(|| integrity.strip_prefix("sha256-"))
        .is_some_and(|value| value.eq_ignore_ascii_case(hex_digest))
    {
        return true;
    }
    integrity.strip_prefix("sha256-").is_some_and(|value| {
        STANDARD
            .decode(value)
            .is_ok_and(|bytes| hex::encode(bytes).eq_ignore_ascii_case(hex_digest))
    })
}

fn is_symlink(path: &Path) -> Option<bool> {
    Some(fs::symlink_metadata(path).ok()?.file_type().is_symlink())
}

fn tree_matches_metadata(
    source: &Path,
    metadata: &CacheMetadata,
    limits: &crate::model::EngineLimits,
) -> bool {
    let mut files = 0u64;
    let mut bytes = 0u64;

    for entry in walkdir::WalkDir::new(source).follow_links(false) {
        let Ok(entry) = entry else {
            return false;
        };
        if entry.file_type().is_symlink() {
            return false;
        }
        if entry.file_type().is_file() {
            let Some(file_count) = files.checked_add(1) else {
                return false;
            };
            let Some(file_bytes) = entry
                .metadata()
                .ok()
                .and_then(|metadata| bytes.checked_add(metadata.len()))
            else {
                return false;
            };
            files = file_count;
            bytes = file_bytes;
        } else if !entry.file_type().is_dir() {
            return false;
        }
    }

    files == metadata.extracted_files
        && bytes == metadata.extracted_bytes
        && hash_tree(source, limits).is_ok_and(|digest| digest == metadata.content_digest)
}

fn write_completion_marker(
    temporary: &Path,
    metadata: &CacheMetadata,
    dependency: &Dependency,
    source_url: &Url,
) -> Result<()> {
    let encoded = serde_json::to_vec_pretty(metadata).map_err(|error| Error::Fetch {
        package: dependency.id(),
        source_url: source_url.to_string(),
        message: error.to_string(),
    })?;
    fs::write(temporary.join(".complete.json"), encoded).map_err(|source| Error::Io {
        operation: "write cache completion marker".to_owned(),
        path: temporary.to_owned(),
        source,
    })
}

fn publish_cache_entry(temporary: &Path, destination: &Path) -> Result<()> {
    if destination.exists() {
        fs::remove_dir_all(destination).map_err(|source| Error::Io {
            operation: "replace incomplete cache entry".to_owned(),
            path: destination.to_owned(),
            source,
        })?;
    }
    fs::rename(temporary, destination).map_err(|source| Error::Io {
        operation: "publish cache entry".to_owned(),
        path: destination.to_owned(),
        source,
    })
}

impl SourceFetcher {
    pub(super) fn destination(&self, dependency: &Dependency) -> std::path::PathBuf {
        let key = hex::encode(Sha256::digest(dependency.id().as_bytes()));
        self.cache.join(dependency.ecosystem.to_string()).join(key)
    }

    pub(super) fn cached(&self, dependency: &Dependency) -> Option<FetchMetadata> {
        let destination = self.destination(dependency);
        let metadata = fs::read(destination.join(".complete.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<CacheMetadata>(&bytes).ok())?;

        if !metadata.matches_dependency(self, dependency) {
            return None;
        }

        let source = metadata.source_path(&destination)?;
        tree_matches_metadata(&source, &metadata, &self.limits)
            .then(|| metadata.into_fetch_metadata(source, true))
    }

    pub(super) fn publish(
        &self,
        dependency: &Dependency,
        source_url: &Url,
        digest: String,
        temporary: &Path,
        source_directory: &Path,
        stats: ExtractionStats,
    ) -> Result<FetchMetadata> {
        let destination = self.destination(dependency);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|source| Error::Io {
                operation: "create ecosystem cache".to_owned(),
                path: parent.to_owned(),
                source,
            })?;
        }

        let relative = source_directory
            .strip_prefix(temporary)
            .map_err(|error| Error::Fetch {
                package: dependency.id(),
                source_url: source_url.to_string(),
                message: error.to_string(),
            })?
            .to_owned();
        let metadata = CacheMetadata::new(
            dependency,
            source_url,
            digest,
            &relative,
            stats,
            hash_tree(source_directory, &self.limits)?,
        );

        write_completion_marker(temporary, &metadata, dependency, source_url)?;
        publish_cache_entry(temporary, &destination)?;
        Ok(metadata.into_fetch_metadata(destination.join(relative), false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cached_fixture() -> (tempfile::TempDir, SourceFetcher, Dependency) {
        let cache = tempfile::tempdir().unwrap();
        let fetcher = SourceFetcher::new(
            cache.path().join("cache"),
            super::super::FetchPolicy::default(),
            crate::model::EngineLimits::default(),
        )
        .unwrap();
        let mut dependency = Dependency::declared(Ecosystem::Npm, "fixture", "1.0.0");
        dependency.resolved_version = Some("1.0.0".to_owned());
        dependency.source_url = Some("https://example.test/fixture.tgz".to_owned());

        let temporary = cache.path().join("temporary");
        let source = temporary.join("package");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("index.js"), b"module.exports = 1;\n").unwrap();
        let bytes = fs::metadata(source.join("index.js")).unwrap().len();
        fetcher
            .publish(
                &dependency,
                &Url::parse("https://example.test/fixture.tgz").unwrap(),
                "sha256:archive-digest".to_owned(),
                &temporary,
                &source,
                ExtractionStats { files: 1, bytes },
            )
            .unwrap();

        assert!(fetcher.cached(&dependency).is_some());
        (cache, fetcher, dependency)
    }

    #[test]
    fn modified_cached_source_is_rejected() {
        let (_cache, fetcher, dependency) = cached_fixture();
        let source = fetcher
            .destination(&dependency)
            .join("package")
            .join("index.js");
        fs::write(source, b"module.exports = 2;\n").unwrap();

        assert!(fetcher.cached(&dependency).is_none());
    }

    #[test]
    fn tampered_source_metadata_is_rejected() {
        let (_cache, fetcher, dependency) = cached_fixture();
        let marker = fetcher.destination(&dependency).join(".complete.json");
        let mut metadata: serde_json::Value =
            serde_json::from_slice(&fs::read(&marker).unwrap()).unwrap();
        metadata["source_url"] =
            serde_json::Value::String("https://attacker.test/fixture.tgz".to_owned());
        fs::write(marker, serde_json::to_vec(&metadata).unwrap()).unwrap();

        assert!(fetcher.cached(&dependency).is_none());
    }

    #[test]
    fn tampered_completion_marker_is_rejected() {
        let (_cache, fetcher, dependency) = cached_fixture();
        fs::write(
            fetcher.destination(&dependency).join(".complete.json"),
            b"{}",
        )
        .unwrap();

        assert!(fetcher.cached(&dependency).is_none());
    }

    #[test]
    fn modified_cached_tree_is_rejected() {
        let (_cache, fetcher, dependency) = cached_fixture();
        let source = fetcher.destination(&dependency).join("package");
        fs::rename(source.join("index.js"), source.join("altered.js")).unwrap();

        assert!(fetcher.cached(&dependency).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_cached_source_is_rejected() {
        use std::os::unix::fs::symlink;

        let (cache, fetcher, dependency) = cached_fixture();
        let destination = fetcher.destination(&dependency);
        let outside = cache.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("index.js"), b"module.exports = 1;\n").unwrap();
        fs::remove_dir_all(destination.join("package")).unwrap();
        symlink(&outside, destination.join("package")).unwrap();

        assert!(fetcher.cached(&dependency).is_none());
    }
}
