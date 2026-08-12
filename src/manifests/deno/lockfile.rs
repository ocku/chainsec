use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use node_semver::{Range as NpmRange, Version as NpmVersion};
use serde_json::Value as JsonValue;

use super::{
    super::shared::{is_file_beneath, manifest_error, read_beneath},
    LockfileSelection, normalize_npm_subpath,
};
use crate::{
    error::Result,
    model::{DenoLockfileSnapshot, Dependency, canonical_deno_remote_url},
};

pub(super) fn enrich(
    root: &Path,
    selection: &LockfileSelection,
    dependencies: &mut [Dependency],
    lockfiles: &mut Vec<PathBuf>,
) -> Result<()> {
    let LockfileSelection::Path(relative) = selection else {
        return Ok(());
    };
    let path = root.join(relative);
    if !is_file_beneath(root, relative)? {
        return Ok(());
    }
    let contents = read_beneath(root, relative)?;
    let lockfile: JsonValue =
        serde_json::from_str(&contents).map_err(|error| manifest_error(&path, error))?;
    let version = validate_lockfile_version(&path, &lockfile)?;
    let snapshot = DenoLockfileSnapshot::from_lockfile(contents.as_bytes(), &lockfile);

    for dependency in dependencies {
        if enrich_dependency(&lockfile, version, dependency) {
            dependency.lockfile = Some(path.clone());
            if dependency.requirement.starts_with("http://")
                || dependency.requirement.starts_with("https://")
            {
                dependency.deno_lockfile_snapshot = Some(snapshot.clone());
            }
        }
    }
    lockfiles.push(path);
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LockVersion {
    Legacy,
    V1,
    V2,
    V3,
    V4,
    V5,
}

pub(super) fn validate_lockfile_version(path: &Path, lockfile: &JsonValue) -> Result<LockVersion> {
    let root = lockfile
        .as_object()
        .ok_or_else(|| manifest_error(path, "Deno lockfile root must be an object"))?;
    let Some(version) = root.get("version") else {
        let is_legacy = !root.is_empty()
            && root.iter().all(|(url, integrity)| {
                (url.starts_with("http://") || url.starts_with("https://")) && integrity.is_string()
            });
        return if is_legacy {
            Ok(LockVersion::Legacy)
        } else {
            Err(manifest_error(
                path,
                "versionless Deno lockfile must use the legacy URL-to-integrity layout",
            ))
        };
    };
    let version = version
        .as_str()
        .ok_or_else(|| manifest_error(path, "Deno lockfile version must be a string"))?;
    match version {
        "1" => Ok(LockVersion::V1),
        "2" => Ok(LockVersion::V2),
        "3" => Ok(LockVersion::V3),
        "4" => Ok(LockVersion::V4),
        "5" => Ok(LockVersion::V5),
        _ => Err(manifest_error(
            path,
            format!("unsupported deno lockfile version {version}"),
        )),
    }
}

pub(super) fn enrich_dependency(
    lockfile: &JsonValue,
    version: LockVersion,
    dependency: &mut Dependency,
) -> bool {
    if dependency.requirement.starts_with("http://")
        || dependency.requirement.starts_with("https://")
    {
        enrich_remote(lockfile, version, dependency)
    } else if dependency.requirement.starts_with("npm:") {
        enrich_npm(lockfile, version, dependency)
    } else if dependency.requirement.starts_with("jsr:") {
        enrich_jsr(lockfile, version, dependency)
    } else {
        false
    }
}

fn enrich_remote(lockfile: &JsonValue, version: LockVersion, dependency: &mut Dependency) -> bool {
    let remote = if version == LockVersion::Legacy {
        lockfile
    } else {
        lockfile.get("remote").unwrap_or(&JsonValue::Null)
    };
    let Some(requirement) = canonical_deno_remote_url(&dependency.requirement) else {
        return false;
    };
    let Some(integrity) = remote
        .as_object()
        .into_iter()
        .flatten()
        .find_map(|(url, integrity)| {
            (canonical_deno_remote_url(url).as_deref() == Some(requirement.as_str()))
                .then(|| integrity.as_str())
                .flatten()
        })
    else {
        return false;
    };
    dependency.integrity = Some(integrity.to_owned());
    dependency.resolved_version = Some(dependency.requirement.clone());
    true
}

fn specifiers(lockfile: &JsonValue, version: LockVersion) -> Option<&JsonValue> {
    match version {
        LockVersion::V2 => lockfile.get("npm")?.get("specifiers"),
        LockVersion::V3 => lockfile.get("packages")?.get("specifiers"),
        LockVersion::V4 | LockVersion::V5 => lockfile.get("specifiers"),
        LockVersion::Legacy | LockVersion::V1 => None,
    }
}

fn packages<'a>(
    lockfile: &'a JsonValue,
    version: LockVersion,
    registry: &str,
) -> Option<&'a JsonValue> {
    match version {
        LockVersion::V2 if registry == "npm" => lockfile.get("npm")?.get("packages"),
        LockVersion::V3 => lockfile.get("packages")?.get(registry),
        LockVersion::V4 | LockVersion::V5 => lockfile.get(registry),
        LockVersion::Legacy | LockVersion::V1 | LockVersion::V2 => None,
    }
}

fn enrich_npm(lockfile: &JsonValue, version: LockVersion, dependency: &mut Dependency) -> bool {
    let normalized_requirement = normalize_npm_subpath(&dependency.requirement);
    let specifier = normalized_requirement
        .strip_prefix("npm:")
        .expect("npm dependencies must have an npm: prefix");
    let Some(name) = registry_package_name(specifier) else {
        return false;
    };
    let specifiers = match specifiers(lockfile, version) {
        Some(specifiers) => specifiers,
        None => return false,
    };
    let Some(locked) = specifiers
        .get(&dependency.requirement)
        .or_else(|| specifiers.get(&normalized_requirement))
        .or_else(|| specifiers.get(specifier))
        .and_then(JsonValue::as_str)
    else {
        return false;
    };
    let normalized_locked = normalize_npm_subpath(locked);
    let locked_key = normalized_locked.strip_prefix("npm:").unwrap_or(locked);
    let resolved = locked_key
        .strip_prefix(name)
        .and_then(|suffix| suffix.strip_prefix('@'))
        .unwrap_or(locked);
    if resolved.is_empty() || !locked_version_compatible(specifier, name, resolved) {
        return false;
    }

    dependency.resolved_version = Some(resolved.to_owned());
    let package_key = if locked_key.starts_with(&format!("{name}@")) {
        locked_key.to_owned()
    } else {
        format!("{name}@{resolved}")
    };
    dependency.integrity = packages(lockfile, version, "npm")
        .and_then(|packages| packages.get(&package_key))
        .and_then(|package| package.get("integrity"))
        .and_then(JsonValue::as_str)
        .map(str::to_owned);
    dependency.registry_integrity_required = dependency.integrity.is_none();
    true
}

fn enrich_jsr(lockfile: &JsonValue, version: LockVersion, dependency: &mut Dependency) -> bool {
    let Some(locked) = specifiers(lockfile, version)
        .and_then(|specifiers| specifiers.get(&dependency.requirement))
        .and_then(JsonValue::as_str)
    else {
        return false;
    };
    let Some(package) = jsr_package_name(&dependency.requirement) else {
        return false;
    };
    let locked_key = locked.strip_prefix("jsr:").unwrap_or(locked);
    let resolved = locked_key
        .strip_prefix(package)
        .and_then(|suffix| suffix.strip_prefix('@'))
        .unwrap_or(locked);
    if resolved.is_empty()
        || !locked_version_compatible(
            dependency
                .requirement
                .strip_prefix("jsr:")
                .unwrap_or(&dependency.requirement),
            package,
            resolved,
        )
    {
        return false;
    }
    dependency.resolved_version = Some(resolved.to_owned());

    let package_key = if locked_key.starts_with(&format!("{package}@")) {
        locked_key.to_owned()
    } else {
        format!("{package}@{resolved}")
    };
    let integrity = packages(lockfile, version, "jsr")
        .and_then(|packages| packages.get(&package_key))
        .and_then(|package| package.get("integrity"))
        .and_then(JsonValue::as_str)
        .filter(|integrity| is_sha256_digest(integrity));
    let Some(integrity) = integrity else {
        return true;
    };

    dependency.integrity = Some(format!("sha256:{integrity}"));
    dependency.source_url = Some(format!("https://jsr.io/{package}/{resolved}_meta.json"));
    true
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn locked_version_compatible(specifier: &str, package: &str, resolved: &str) -> bool {
    let Ok(version) = NpmVersion::from_str(resolved) else {
        return false;
    };
    let Some(range) = specifier
        .strip_prefix(package)
        .and_then(|suffix| suffix.strip_prefix('@'))
    else {
        return true;
    };
    let Ok(range) = NpmRange::from_str(range) else {
        return false;
    };
    range.satisfies(&version)
}

fn jsr_package_name(requirement: &str) -> Option<&str> {
    registry_package_name(requirement.strip_prefix("jsr:")?)
}

fn registry_package_name(specifier: &str) -> Option<&str> {
    if specifier.is_empty() {
        return None;
    }
    let separator = specifier.rfind('@').filter(|index| *index > 0);
    Some(separator.map_or(specifier, |index| &specifier[..index]))
}
