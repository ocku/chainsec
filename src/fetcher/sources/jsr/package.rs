use std::{
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

use sha2::{Digest, Sha256};
use url::Url;

use crate::fetcher::{
    SourceFetcher,
    archive::{ExtractionStats, account_extracted_entry, safe_relative},
    cache::{is_unsafe_cache_open_error, write_cached_artifact},
    filesystem::TrustedDir,
    integrity::{verify_integrity, verify_jsr_checksum},
};
use crate::{
    error::{Error, Result},
    model::EngineLimits,
};

use super::resolution::{JsrManifestEntry, JsrVersionMetadata};

impl SourceFetcher {
    #[cfg(test)]
    pub(in crate::fetcher) async fn fetch_jsr_package(
        &self,
        metadata_url: &Url,
        temporary: &Path,
        expected: Option<&str>,
    ) -> Result<(PathBuf, String, ExtractionStats)> {
        let mut network_budget = self.network_budget();
        self.fetch_jsr_package_with_budget(metadata_url, temporary, expected, &mut network_budget)
            .await
            .map(|(source, digest, stats, _)| (source, digest, stats))
    }

    pub(in crate::fetcher) async fn fetch_jsr_package_with_budget(
        &self,
        metadata_url: &Url,
        temporary: &Path,
        expected: Option<&str>,
        network_budget: &mut crate::fetcher::network::NetworkBudget,
    ) -> Result<(PathBuf, String, ExtractionStats, Url)> {
        let repository_base = self
            .policy
            .repositories
            .repository_base_for(metadata_url)
            .expect("JSR metadata URLs are built from a configured repository");
        let (metadata_bytes, effective_metadata_url) = self
            .download_with_effective_url_and_budget_from_repository(
                metadata_url,
                &repository_base,
                network_budget,
            )
            .await?;
        verify_integrity(&metadata_bytes, expected, effective_metadata_url.as_str())?;
        write_cached_artifact(temporary, &metadata_bytes)?;
        let metadata: JsrVersionMetadata =
            serde_json::from_slice(&metadata_bytes).map_err(|error| Error::Fetch {
                package: "jsr package".to_owned(),
                source_url: crate::fetcher::network::diagnostic_url(&effective_metadata_url),
                message: format!("invalid JSR version metadata: {error}"),
            })?;
        check_manifest_limits(&metadata, &self.limits)?;

        let source = temporary.join("source");
        let temporary_root = TrustedDir::open(temporary).map_err(|source_error| Error::Io {
            operation: "open JSR workspace".to_owned(),
            path: temporary.to_owned(),
            source: source_error,
        })?;
        temporary_root
            .create_dir_all(Path::new("source"))
            .map_err(|source_error| Error::Io {
                operation: "create JSR source directory".to_owned(),
                path: source.clone(),
                source: source_error,
            })?;
        let source_root = temporary_root
            .open_subdirectory(Path::new("source"))
            .map_err(|source_error| Error::Io {
                operation: "open JSR source directory".to_owned(),
                path: source.clone(),
                source: source_error,
            })?;
        let file_base_url = jsr_file_base_url(&effective_metadata_url)?;
        let mut stats = ExtractionStats::default();
        for (manifest_path, entry) in metadata.manifest {
            let relative = jsr_manifest_path(&manifest_path, self.limits.max_file_depth)?;
            let file_url = jsr_file_url(&file_base_url, relative)?;
            let bytes = self
                .download_with_budget_from_repository(&file_url, &repository_base, network_budget)
                .await?;

            verify_jsr_file(&bytes, &entry, &file_url)?;
            account_extracted_entry(&mut stats, bytes.len() as u64, &self.limits)?;
            write_jsr_file(&source_root, relative, &source.join(relative), &bytes)?;
        }
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&metadata_bytes)));
        Ok((source, digest, stats, effective_metadata_url))
    }

    pub(in crate::fetcher) fn rebuild_cached_jsr_package(
        &self,
        metadata_url: &Url,
        temporary: &Path,
        expected: Option<&str>,
        metadata_bytes: &[u8],
        cached_source: &Path,
    ) -> Result<(PathBuf, String, ExtractionStats)> {
        verify_integrity(metadata_bytes, expected, metadata_url.as_str())?;
        let metadata: JsrVersionMetadata =
            serde_json::from_slice(metadata_bytes).map_err(|error| Error::Fetch {
                package: "jsr package".to_owned(),
                source_url: metadata_url.to_string(),
                message: format!("invalid cached JSR version metadata: {error}"),
            })?;
        check_manifest_limits(&metadata, &self.limits)?;
        write_cached_artifact(temporary, metadata_bytes)?;

        let source = temporary.join("source");
        let temporary_root = TrustedDir::open(temporary).map_err(|source_error| Error::Io {
            operation: "open JSR workspace".to_owned(),
            path: temporary.to_owned(),
            source: source_error,
        })?;
        temporary_root
            .create_dir_all(Path::new("source"))
            .map_err(|source_error| Error::Io {
                operation: "create JSR source directory".to_owned(),
                path: source.clone(),
                source: source_error,
            })?;
        let source_root = temporary_root
            .open_subdirectory(Path::new("source"))
            .map_err(|source_error| Error::Io {
                operation: "open JSR source directory".to_owned(),
                path: source.clone(),
                source: source_error,
            })?;
        let cached_root = open_cached_jsr_directory(cached_source)?;
        let file_base_url = jsr_file_base_url(metadata_url)?;
        let mut stats = ExtractionStats::default();
        for (manifest_path, entry) in metadata.manifest {
            let relative = jsr_manifest_path(&manifest_path, self.limits.max_file_depth)?;
            let file_url = jsr_file_url(&file_base_url, relative)?;
            let bytes = read_cached_jsr_file(&cached_root, cached_source, relative, entry.size)?;

            verify_jsr_file(&bytes, &entry, &file_url)?;
            account_extracted_entry(&mut stats, bytes.len() as u64, &self.limits)?;
            write_jsr_file(&source_root, relative, &source.join(relative), &bytes)?;
        }
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(metadata_bytes)));
        Ok((source, digest, stats))
    }
}

fn check_manifest_limits(metadata: &JsrVersionMetadata, limits: &EngineLimits) -> Result<()> {
    let declared_bytes = metadata
        .manifest
        .values()
        .try_fold(0u64, |total, entry| total.checked_add(entry.size))
        .ok_or_else(|| Error::LimitExceeded {
            resource: "JSR package bytes".to_owned(),
            limit: limits.max_extracted_size,
        })?;

    if metadata.manifest.len() as u64 > limits.max_extracted_files {
        return Err(Error::LimitExceeded {
            resource: "JSR package files".to_owned(),
            limit: limits.max_extracted_files,
        });
    }
    if declared_bytes > limits.max_extracted_size {
        return Err(Error::LimitExceeded {
            resource: "JSR package bytes".to_owned(),
            limit: limits.max_extracted_size,
        });
    }
    Ok(())
}

fn jsr_file_base_url(metadata_url: &Url) -> Result<Url> {
    let base_path = metadata_url
        .path()
        .strip_suffix("_meta.json")
        .ok_or_else(|| Error::Resolution {
            package: "jsr package".to_owned(),
            message: format!("JSR metadata URL does not end in _meta.json: {metadata_url}"),
        })?;
    let mut base_url = metadata_url.clone();
    base_url.set_path(&format!("{base_path}/"));
    base_url.set_query(None);
    base_url.set_fragment(None);
    Ok(base_url)
}

fn jsr_manifest_path(manifest_path: &str, max_file_depth: usize) -> Result<&Path> {
    let raw = manifest_path
        .strip_prefix('/')
        .ok_or_else(|| Error::Policy {
            operation: "JSR extraction".to_owned(),
            message: format!("JSR manifest path must begin with /: {manifest_path}"),
        })?;
    if raw.is_empty() || raw.contains('\\') {
        return Err(Error::Policy {
            operation: "JSR extraction".to_owned(),
            message: format!("unsafe JSR manifest path: {manifest_path}"),
        });
    }

    let relative = Path::new(raw);
    if !safe_relative(relative, max_file_depth)
        || relative
            .components()
            .any(|component| matches!(component, Component::CurDir))
    {
        return Err(Error::Policy {
            operation: "JSR extraction".to_owned(),
            message: format!("unsafe JSR manifest path: {manifest_path}"),
        });
    }
    Ok(relative)
}

fn jsr_file_url(base_url: &Url, relative: &Path) -> Result<Url> {
    let mut file_url = base_url.clone();
    {
        let mut segments = file_url
            .path_segments_mut()
            .map_err(|_| Error::Resolution {
                package: "jsr package".to_owned(),
                message: "JSR URL cannot contain path segments".to_owned(),
            })?;
        segments.pop_if_empty();
        for component in relative.components() {
            if let Component::Normal(value) = component {
                let value = value.to_str().ok_or_else(|| Error::Policy {
                    operation: "JSR extraction".to_owned(),
                    message: "JSR manifest path is not UTF-8".to_owned(),
                })?;
                segments.push(value);
            }
        }
    }
    Ok(file_url)
}

fn verify_jsr_file(bytes: &[u8], entry: &JsrManifestEntry, file_url: &Url) -> Result<()> {
    if bytes.len() as u64 != entry.size {
        return Err(Error::Fetch {
            package: "jsr package".to_owned(),
            source_url: file_url.to_string(),
            message: format!(
                "size mismatch: expected {}, received {}",
                entry.size,
                bytes.len()
            ),
        });
    }
    verify_jsr_checksum(bytes, &entry.checksum, file_url.as_str())
}

fn open_cached_jsr_directory(source: &Path) -> Result<TrustedDir> {
    TrustedDir::open(source).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound || is_unsafe_cache_open_error(&error) {
            Error::Policy {
                operation: "cache validation".to_owned(),
                message: format!(
                    "cached JSR source is missing or unsafe: {}",
                    source.display()
                ),
            }
        } else {
            Error::Io {
                operation: "open cached JSR source".to_owned(),
                path: source.to_owned(),
                source: error,
            }
        }
    })
}

pub(super) fn read_cached_jsr_file(
    source: &TrustedDir,
    source_path: &Path,
    relative: &Path,
    expected_size: u64,
) -> Result<Vec<u8>> {
    let path = source_path.join(relative);
    let file = source.open_file_no_follow(relative).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound || is_unsafe_cache_open_error(&error) {
            Error::Policy {
                operation: "cache validation".to_owned(),
                message: format!("cached JSR file is missing or unsafe: {}", path.display()),
            }
        } else {
            Error::Io {
                operation: "open cached JSR file".to_owned(),
                path: path.clone(),
                source: error,
            }
        }
    })?;
    let metadata = file.metadata().map_err(|source| Error::Io {
        operation: "inspect opened cached JSR file".to_owned(),
        path: path.clone(),
        source,
    })?;
    if !metadata.is_file() || metadata.len() != expected_size {
        return Err(Error::Policy {
            operation: "cache validation".to_owned(),
            message: format!(
                "cached JSR file size mismatch or is unsafe: {}",
                path.display()
            ),
        });
    }
    let mut bytes = Vec::with_capacity(usize::try_from(expected_size).unwrap_or(0));
    file.take(expected_size.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| Error::Io {
            operation: "read cached JSR file".to_owned(),
            path: path.clone(),
            source,
        })?;
    if bytes.len() as u64 != expected_size {
        return Err(Error::Policy {
            operation: "cache validation".to_owned(),
            message: format!("cached JSR file changed while reading: {}", path.display()),
        });
    }
    Ok(bytes)
}

fn write_jsr_file(root: &TrustedDir, relative: &Path, output: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = root.create_new_file(relative).map_err(|source| Error::Io {
        operation: "create JSR source file".to_owned(),
        path: output.to_owned(),
        source,
    })?;
    file.write_all(bytes).map_err(|source| Error::Io {
        operation: "write JSR source file".to_owned(),
        path: output.to_owned(),
        source,
    })
}
