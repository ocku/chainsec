use std::{
    fs,
    path::{Component, Path},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    error::{Error, Result},
    model::{Dependency, Ecosystem, FetchMetadata},
};

use super::{SafeSourceFetcher, archive::ExtractionStats, integrity::hash_tree};

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

impl SafeSourceFetcher {
    pub(super) fn destination(&self, dependency: &Dependency) -> std::path::PathBuf {
        let key = hex::encode(Sha256::digest(dependency.id().as_bytes()));
        self.cache.join(dependency.ecosystem.to_string()).join(key)
    }

    pub(super) fn cached(&self, dependency: &Dependency) -> Option<FetchMetadata> {
        let destination = self.destination(dependency);
        let metadata = fs::read(destination.join(".complete.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<CacheMetadata>(&bytes).ok())?;

        let expected_version = dependency
            .resolved_version
            .as_deref()
            .unwrap_or(&dependency.requirement);
        if metadata.package_id != dependency.id()
            || metadata.resolved_version != expected_version
            || metadata.integrity.as_deref() != dependency.integrity.as_deref()
            || metadata.fetcher_version != env!("CARGO_PKG_VERSION")
            || metadata.source_url.is_empty()
            || !Url::parse(&metadata.source_url)
                .ok()
                .is_some_and(|url| matches!(url.scheme(), "http" | "https"))
            || dependency
                .source_url
                .as_deref()
                .is_some_and(|source_url| source_url != metadata.source_url)
            || metadata.digest.is_empty()
            || !integrity_matches_digest(dependency.integrity.as_deref(), &metadata.digest)
            || metadata.content_digest.is_empty()
            || metadata.extracted_files > self.limits.max_extracted_files
            || metadata.extracted_bytes > self.limits.max_extracted_bytes
            || (dependency.ecosystem == Ecosystem::Deno
                && !dependency.requirement.starts_with("jsr:")
                && metadata.extracted_files > self.policy.max_deno_modules as u64)
        {
            return None;
        }

        let source_directory = Path::new(&metadata.source_directory);
        if source_directory.is_absolute()
            || source_directory
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return None;
        }
        let source = destination.join(source_directory);
        if fs::symlink_metadata(&destination)
            .ok()?
            .file_type()
            .is_symlink()
            || fs::symlink_metadata(&source).ok()?.file_type().is_symlink()
        {
            return None;
        }
        let destination = fs::canonicalize(&destination).ok()?;
        let source = fs::canonicalize(source).ok()?;
        if !source.starts_with(&destination) || !source.is_dir() {
            return None;
        }

        let mut files = 0u64;
        let mut bytes = 0u64;
        for entry in walkdir::WalkDir::new(&source).follow_links(false) {
            let entry = entry.ok()?;
            if entry.file_type().is_symlink() {
                return None;
            }
            if entry.file_type().is_file() {
                files = files.checked_add(1)?;
                bytes = bytes.checked_add(entry.metadata().ok()?.len())?;
            } else if !entry.file_type().is_dir() {
                return None;
            }
        }
        if files != metadata.extracted_files || bytes != metadata.extracted_bytes {
            return None;
        }
        let content_digest = hash_tree(&source, &self.limits).ok()?;
        if content_digest != metadata.content_digest {
            return None;
        }

        Some(FetchMetadata {
            source,
            package_id: metadata.package_id,
            resolved_version: metadata.resolved_version,
            digest: metadata.digest,
            source_url: metadata.source_url,
            cache_hit: true,
        })
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
            })?;
        let content_digest = hash_tree(source_directory, &self.limits)?;
        let metadata = CacheMetadata {
            package_id: dependency.id(),
            resolved_version: dependency
                .resolved_version
                .clone()
                .unwrap_or_else(|| dependency.requirement.clone()),
            integrity: dependency.integrity.clone(),
            digest: digest.clone(),
            source_url: source_url.to_string(),
            source_directory: relative.to_string_lossy().into_owned(),
            extracted_files: stats.files,
            extracted_bytes: stats.bytes,
            content_digest,
            fetcher_version: env!("CARGO_PKG_VERSION").to_owned(),
        };
        let encoded = serde_json::to_vec_pretty(&metadata).map_err(|error| Error::Fetch {
            package: dependency.id(),
            source_url: source_url.to_string(),
            message: error.to_string(),
        })?;
        fs::write(temporary.join(".complete.json"), encoded).map_err(|source| Error::Io {
            operation: "write cache completion marker".to_owned(),
            path: temporary.to_owned(),
            source,
        })?;
        if destination.exists() {
            fs::remove_dir_all(&destination).map_err(|source| Error::Io {
                operation: "replace incomplete cache entry".to_owned(),
                path: destination.clone(),
                source,
            })?;
        }
        fs::rename(temporary, &destination).map_err(|source| Error::Io {
            operation: "publish cache entry".to_owned(),
            path: destination.clone(),
            source,
        })?;
        Ok(FetchMetadata {
            source: destination.join(relative),
            package_id: metadata.package_id,
            resolved_version: metadata.resolved_version,
            digest,
            source_url: metadata.source_url,
            cache_hit: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cached_fixture() -> (tempfile::TempDir, SafeSourceFetcher, Dependency) {
        let cache = tempfile::tempdir().unwrap();
        let fetcher = SafeSourceFetcher::new(
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
