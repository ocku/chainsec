use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Write,
    path::{Component, Path, PathBuf},
    str::FromStr,
};

use node_semver::{Range as NpmRange, Version as NpmVersion};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    error::{Error, Result},
    model::{Dependency, EngineLimits},
};

use crate::fetcher::{
    SourceFetcher,
    archive::{ExtractionStats, check_extraction_limits, safe_relative},
    integrity::{verify_integrity, verify_jsr_checksum},
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
    pub(in crate::fetcher) async fn resolve_unlocked_jsr(
        &self,
        dependency: &mut Dependency,
    ) -> Result<()> {
        let (package, requirement) = jsr_package_and_requirement(dependency)?;
        let metadata_url = self.policy.repositories.jsr_package_metadata_url(package)?;
        let metadata: JsonValue = serde_json::from_slice(&self.download(&metadata_url).await?)
            .map_err(|error| Error::Resolution {
                package: dependency.id(),
                message: format!("invalid JSR registry response: {error}"),
            })?;
        let version = select_jsr_version(dependency, requirement, &metadata)?;
        let version_metadata_url = self
            .policy
            .repositories
            .jsr_version_metadata_url(package, &version)?;
        let version_metadata = self.download(&version_metadata_url).await?;

        dependency.resolved_version = Some(version);
        dependency.source_url = Some(version_metadata_url.to_string());
        dependency.integrity = Some(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(version_metadata))
        ));
        Ok(())
    }

    pub(in crate::fetcher) async fn fetch_jsr_package(
        &self,
        metadata_url: &Url,
        temporary: &Path,
        expected: Option<&str>,
    ) -> Result<(PathBuf, String, ExtractionStats)> {
        let metadata_bytes = self.download(metadata_url).await?;
        verify_integrity(&metadata_bytes, expected, metadata_url.as_str())?;
        let metadata: JsrVersionMetadata =
            serde_json::from_slice(&metadata_bytes).map_err(|error| Error::Fetch {
                package: "jsr package".to_owned(),
                source_url: metadata_url.to_string(),
                message: format!("invalid JSR version metadata: {error}"),
            })?;
        check_manifest_limits(&metadata, &self.limits)?;

        let source = temporary.join("source");
        create_jsr_directory(&source)?;
        let file_base_url = jsr_file_base_url(metadata_url)?;
        let mut stats = ExtractionStats::default();
        for (manifest_path, entry) in metadata.manifest {
            let relative = jsr_manifest_path(&manifest_path)?;
            let file_url = jsr_file_url(&file_base_url, relative)?;
            let bytes = self.download(&file_url).await?;

            verify_jsr_file(&bytes, &entry, &file_url)?;
            record_jsr_file(&mut stats, bytes.len() as u64, &self.limits)?;
            write_jsr_file(&source.join(relative), &bytes)?;
        }
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&metadata_bytes)));
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

fn create_jsr_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|source| Error::Io {
        operation: "create JSR source directory".to_owned(),
        path: path.to_owned(),
        source,
    })
}

fn jsr_file_base_url(metadata_url: &Url) -> Result<Url> {
    let base = metadata_url
        .as_str()
        .strip_suffix("_meta.json")
        .ok_or_else(|| Error::Resolution {
            package: "jsr package".to_owned(),
            message: "JSR metadata URL does not end in _meta.json".to_owned(),
        })?;
    Url::parse(&format!("{base}/")).map_err(|error| Error::Resolution {
        package: "jsr package".to_owned(),
        message: error.to_string(),
    })
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

fn write_jsr_file(output: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = output.parent() {
        create_jsr_directory(parent)?;
    }
    let mut file = File::options()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|source| Error::Io {
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

fn jsr_package_and_requirement(dependency: &Dependency) -> Result<(&str, &str)> {
    let specifier =
        dependency
            .requirement
            .strip_prefix("jsr:")
            .ok_or_else(|| Error::Resolution {
                package: dependency.id(),
                message: "JSR dependency must begin with jsr:".to_owned(),
            })?;
    match specifier.rsplit_once('@') {
        Some((package, requirement)) if !package.is_empty() => Ok((package, requirement)),
        _ if !specifier.is_empty() => Ok((specifier, "*")),
        _ => Err(Error::Resolution {
            package: dependency.id(),
            message: "JSR dependency has no package name".to_owned(),
        }),
    }
}

fn select_jsr_version(
    dependency: &Dependency,
    requirement: &str,
    metadata: &JsonValue,
) -> Result<String> {
    let versions = metadata
        .get("versions")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| Error::Resolution {
            package: dependency.id(),
            message: "JSR registry response has no versions".to_owned(),
        })?;
    let range = NpmRange::from_str(requirement).map_err(|_| Error::Resolution {
        package: dependency.id(),
        message: format!("invalid JSR version requirement {requirement}"),
    })?;
    versions
        .iter()
        .filter(|(_, release)| {
            !release
                .get("yanked")
                .and_then(JsonValue::as_bool)
                .unwrap_or(false)
        })
        .filter_map(|(raw_version, _)| {
            let version = NpmVersion::from_str(raw_version).ok()?;
            range.satisfies(&version).then_some(version)
        })
        .max()
        .map(|version| version.to_string())
        .ok_or_else(|| Error::Resolution {
            package: dependency.id(),
            message: format!("JSR registry has no release satisfying {requirement}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Ecosystem;

    #[test]
    fn selects_highest_non_yanked_jsr_release_matching_requirement() {
        let dependency = Dependency::declared(Ecosystem::Deno, "assert", "jsr:@std/assert@^1.0.0");
        let metadata = serde_json::json!({
            "versions": {
                "1.0.0": {},
                "1.2.0": {},
                "1.3.0": { "yanked": true },
                "2.0.0": {}
            }
        });

        assert_eq!(
            select_jsr_version(&dependency, "^1.0.0", &metadata).unwrap(),
            "1.2.0"
        );
    }

    #[test]
    fn parses_unversioned_scoped_jsr_package() {
        let dependency = Dependency::declared(Ecosystem::Deno, "assert", "jsr:@std/assert");

        assert_eq!(
            jsr_package_and_requirement(&dependency).unwrap(),
            ("@std/assert", "*")
        );
    }
}
