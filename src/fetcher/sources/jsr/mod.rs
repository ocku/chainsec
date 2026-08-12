use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

#[cfg(test)]
use std::fs;

use serde::Deserialize;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    error::{Error, Result},
    model::{Dependency, EngineLimits},
};

use crate::fetcher::{
    RemoteVersionSelection, SourceFetcher,
    archive::{ExtractionStats, check_extraction_limits, safe_relative},
    cache::{is_unsafe_cache_open_error, write_cached_artifact},
    filesystem::TrustedDir,
    integrity::{verify_integrity, verify_jsr_checksum},
    network::diagnostic_url,
};

#[derive(Debug, Deserialize)]
struct JsrVersionMetadata {
    manifest: BTreeMap<String, JsrManifestEntry>,
}

#[derive(Debug, Deserialize)]
struct JsrManifestEntry {
    size: u64,
    checksum: String,
}

impl SourceFetcher {
    #[allow(dead_code)]
    pub(in crate::fetcher) async fn resolve_unlocked_jsr(
        &self,
        dependency: &mut Dependency,
    ) -> Result<()> {
        let mut budget = self.network_budget();
        self.resolve_unlocked_jsr_with_budget(dependency, &mut budget)
            .await
    }

    pub(in crate::fetcher) async fn resolve_unlocked_jsr_with_budget(
        &self,
        dependency: &mut Dependency,
        budget: &mut crate::fetcher::network::NetworkBudget,
    ) -> Result<()> {
        let (package, requirement) = jsr_package_and_requirement(dependency)?;
        let package = package.to_owned();
        let requirement = requirement.to_owned();
        let metadata = self
            .jsr_package_metadata_with_budget(dependency, &package, budget)
            .await?;
        let version = select_jsr_version(dependency, &requirement, &metadata)?;
        self.pin_jsr_version_with_budget(dependency, &package, version, budget)
            .await
    }

    #[allow(dead_code)]
    pub(in crate::fetcher) async fn resolve_jsr_version_selection(
        &self,
        dependency: Dependency,
        selection: RemoteVersionSelection,
    ) -> Result<Vec<Dependency>> {
        let mut budget = self.network_budget();
        self.resolve_jsr_version_selection_with_budget(dependency, selection, &mut budget)
            .await
    }

    pub(in crate::fetcher) async fn resolve_jsr_version_selection_with_budget(
        &self,
        dependency: Dependency,
        selection: RemoteVersionSelection,
        budget: &mut crate::fetcher::network::NetworkBudget,
    ) -> Result<Vec<Dependency>> {
        let (package, requirement) = jsr_package_and_requirement(&dependency)?;
        let package = package.to_owned();
        let metadata = self
            .jsr_package_metadata_with_budget(&dependency, &package, budget)
            .await?;
        match selection {
            RemoteVersionSelection::Last(count) => {
                let selected = select_jsr_version(&dependency, requirement, &metadata)?;
                let versions = jsr_versions_at_or_below(&dependency, &selected, &metadata)?;
                let mut resolved = Vec::new();
                let mut candidates_checked = 0;

                for version in versions {
                    candidates_checked += 1;
                    self.enforce_remote_version_candidate_limit(candidates_checked)?;
                    let mut candidate = dependency.clone();
                    match self
                        .pin_jsr_version_with_budget(&mut candidate, &package, version, budget)
                        .await
                    {
                        Ok(()) => {
                            resolved.push(candidate);
                            self.enforce_remote_version_limit(resolved.len())?;
                            if resolved.len() == count {
                                break;
                            }
                        }
                        Err(error) if historical_jsr_version_unavailable(&error) => {}
                        Err(error) => return Err(error),
                    }
                }
                Ok(resolved)
            }
            RemoteVersionSelection::Compare { from, to } => {
                let versions = jsr_compare_versions(&dependency, &from, &to, &metadata)?;
                let mut resolved = Vec::with_capacity(versions.len());
                for (index, version) in versions.into_iter().enumerate() {
                    self.enforce_remote_version_candidate_limit(index + 1)?;
                    let endpoint = if version == to { "TO" } else { "FROM" };
                    let mut candidate = dependency.clone();
                    self.pin_jsr_version_with_budget(
                        &mut candidate,
                        &package,
                        version.clone(),
                        budget,
                    )
                    .await
                    .map_err(|error| jsr_endpoint_error(&dependency, endpoint, &version, error))?;
                    resolved.push(candidate);
                    self.enforce_remote_version_limit(resolved.len())?;
                }
                Ok(resolved)
            }
            RemoteVersionSelection::Range { from, to } => {
                let versions = jsr_range_versions(&dependency, &from, &to, &metadata)?;
                let mut resolved = Vec::with_capacity(versions.len());
                for (index, version) in versions.into_iter().enumerate() {
                    self.enforce_remote_version_candidate_limit(index + 1)?;
                    let mut candidate = dependency.clone();
                    match self
                        .pin_jsr_version_with_budget(
                            &mut candidate,
                            &package,
                            version.clone(),
                            budget,
                        )
                        .await
                    {
                        Ok(()) => {
                            resolved.push(candidate);
                            self.enforce_remote_version_limit(resolved.len())?;
                        }
                        Err(error) if version == from => {
                            return Err(jsr_endpoint_error(&dependency, "FROM", &version, error));
                        }
                        Err(error) if version == to => {
                            return Err(jsr_endpoint_error(&dependency, "TO", &version, error));
                        }
                        Err(error) if historical_jsr_version_unavailable(&error) => {}
                        Err(error) => return Err(error),
                    }
                }
                Ok(resolved)
            }
        }
    }

    #[allow(dead_code)]
    async fn jsr_package_metadata(
        &self,
        dependency: &Dependency,
        package: &str,
    ) -> Result<JsonValue> {
        let mut budget = self.network_budget();
        self.jsr_package_metadata_with_budget(dependency, package, &mut budget)
            .await
    }

    async fn jsr_package_metadata_with_budget(
        &self,
        dependency: &Dependency,
        package: &str,
        budget: &mut crate::fetcher::network::NetworkBudget,
    ) -> Result<JsonValue> {
        let metadata_url = self.policy.repositories.jsr_package_metadata_url(package)?;
        serde_json::from_slice(
            &self
                .download_with_budget(&metadata_url, true, budget)
                .await?,
        )
        .map_err(|error| Error::Resolution {
            package: dependency.id(),
            message: format!("invalid JSR registry response: {error}"),
        })
    }

    #[allow(dead_code)]
    async fn pin_jsr_version(
        &self,
        dependency: &mut Dependency,
        package: &str,
        version: String,
    ) -> Result<()> {
        let mut budget = self.network_budget();
        self.pin_jsr_version_with_budget(dependency, package, version, &mut budget)
            .await
    }

    async fn pin_jsr_version_with_budget(
        &self,
        dependency: &mut Dependency,
        package: &str,
        version: String,
        budget: &mut crate::fetcher::network::NetworkBudget,
    ) -> Result<()> {
        let version_metadata_url = self
            .policy
            .repositories
            .jsr_version_metadata_url(package, &version)?;
        let (version_metadata, effective_metadata_url) = self
            .download_with_effective_url_and_budget(&version_metadata_url, true, budget)
            .await?;
        serde_json::from_slice::<JsrVersionMetadata>(&version_metadata).map_err(|error| {
            Error::Resolution {
                package: dependency.id(),
                message: format!(
                    "invalid JSR version metadata: response from {}: {error}",
                    diagnostic_url(&effective_metadata_url)
                ),
            }
        })?;

        dependency.resolved_version = Some(version);
        dependency.source_url = Some(version_metadata_url.to_string());
        dependency.integrity = Some(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(version_metadata))
        ));
        Ok(())
    }

    #[allow(dead_code)]
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
        let (metadata_bytes, effective_metadata_url) = self
            .download_with_effective_url_and_budget(metadata_url, true, network_budget)
            .await?;
        verify_integrity(&metadata_bytes, expected, effective_metadata_url.as_str())?;
        write_cached_artifact(temporary, &metadata_bytes)?;
        let metadata: JsrVersionMetadata =
            serde_json::from_slice(&metadata_bytes).map_err(|error| Error::Fetch {
                package: "jsr package".to_owned(),
                source_url: diagnostic_url(&effective_metadata_url),
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
            let relative = jsr_manifest_path(&manifest_path)?;
            let file_url = jsr_file_url(&file_base_url, relative)?;
            let bytes = self
                .download_with_budget(&file_url, true, network_budget)
                .await?;

            verify_jsr_file(&bytes, &entry, &file_url)?;
            record_jsr_file(&mut stats, bytes.len() as u64, &self.limits)?;
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
            let relative = jsr_manifest_path(&manifest_path)?;
            let file_url = jsr_file_url(&file_base_url, relative)?;
            let bytes = read_cached_jsr_file(&cached_root, cached_source, relative, entry.size)?;

            verify_jsr_file(&bytes, &entry, &file_url)?;
            record_jsr_file(&mut stats, bytes.len() as u64, &self.limits)?;
            write_jsr_file(&source_root, relative, &source.join(relative), &bytes)?;
        }
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(metadata_bytes)));
        Ok((source, digest, stats))
    }
}

fn jsr_endpoint_error(
    dependency: &Dependency,
    endpoint: &str,
    version: &str,
    error: Error,
) -> Error {
    Error::Resolution {
        package: dependency.id(),
        message: format!("JSR {endpoint} endpoint {version} is not pullable: {error}"),
    }
}

fn historical_jsr_version_unavailable(error: &Error) -> bool {
    if let Error::Fetch { message, .. } = error {
        message.starts_with("HTTP 404") || message.starts_with("HTTP 410")
    } else {
        false
    }
}

fn check_manifest_limits(metadata: &JsrVersionMetadata, limits: &EngineLimits) -> Result<()> {
    let declared_bytes = metadata
        .manifest
        .values()
        .try_fold(0u64, |total, entry| total.checked_add(entry.size))
        .ok_or_else(|| Error::LimitExceeded {
            resource: "JSR package bytes".to_owned(),
            limit: limits.max_extracted_bytes,
        })?;

    if metadata.manifest.len() as u64 > limits.max_extracted_files {
        return Err(Error::LimitExceeded {
            resource: "JSR package files".to_owned(),
            limit: limits.max_extracted_files,
        });
    }
    if declared_bytes > limits.max_extracted_bytes {
        return Err(Error::LimitExceeded {
            resource: "JSR package bytes".to_owned(),
            limit: limits.max_extracted_bytes,
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

fn jsr_manifest_path(manifest_path: &str) -> Result<&Path> {
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
    if !safe_relative(relative)
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

fn record_jsr_file(stats: &mut ExtractionStats, bytes: u64, limits: &EngineLimits) -> Result<()> {
    stats.files += 1;
    stats.bytes = stats.bytes.saturating_add(bytes);
    check_extraction_limits(stats, limits)
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

fn read_cached_jsr_file(
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

mod selection;
use selection::{
    jsr_compare_versions, jsr_package_and_requirement, jsr_range_versions,
    jsr_versions_at_or_below, select_jsr_version,
};

#[cfg(test)]
mod tests;
