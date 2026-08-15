use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    str::FromStr,
};

use node_semver::{Range as NpmRange, Version as NpmVersion};
use serde_json::Value as JsonValue;

use super::{
    super::shared::{is_file_beneath, is_npm_dist_tag, manifest_error, read_beneath},
    LockfileSelection,
    import_map::{normalize_jsr_subpath, normalize_npm_subpath},
};
use crate::{
    error::Result,
    model::{DenoLockfileSnapshot, Dependency, canonical_http_url},
};

pub(super) fn enrich(
    root: &Path,
    selection: &LockfileSelection,
    dependencies: &mut [Dependency],
    lockfiles: &mut Vec<PathBuf>,
    max_redirect_hops: usize,
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
    let remote_indexes = RemoteIndexes::new(&path, &lockfile, version, max_redirect_hops)?;

    for dependency in dependencies {
        if enrich_dependency_with_remote_indexes(&lockfile, version, dependency, &remote_indexes) {
            dependency.lockfile = Some(path.clone());
            if canonical_http_url(&dependency.requirement).is_some() {
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
            && root
                .iter()
                .all(|(url, integrity)| canonical_http_url(url).is_some() && integrity.is_string());
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

#[cfg(test)]
pub(super) fn enrich_dependency(
    lockfile: &JsonValue,
    version: LockVersion,
    dependency: &mut Dependency,
) -> bool {
    enrich_dependency_with_redirect_limit(
        lockfile,
        version,
        dependency,
        crate::model::EngineLimits::default().max_redirect_hops,
    )
}

#[cfg(test)]
pub(super) fn enrich_dependency_with_redirect_limit(
    lockfile: &JsonValue,
    version: LockVersion,
    dependency: &mut Dependency,
    max_redirect_hops: usize,
) -> bool {
    let remote_indexes =
        RemoteIndexes::new(Path::new("deno.lock"), lockfile, version, max_redirect_hops)
            .expect("test lockfile remote indexes must be valid");
    enrich_dependency_with_remote_indexes(lockfile, version, dependency, &remote_indexes)
}

fn enrich_dependency_with_remote_indexes(
    lockfile: &JsonValue,
    version: LockVersion,
    dependency: &mut Dependency,
    remote_indexes: &RemoteIndexes<'_>,
) -> bool {
    if canonical_http_url(&dependency.requirement).is_some() {
        enrich_remote(dependency, remote_indexes)
    } else if dependency.requirement.starts_with("npm:") {
        enrich_npm(lockfile, version, dependency)
    } else if dependency.requirement.starts_with("jsr:") {
        enrich_jsr(lockfile, version, dependency)
    } else {
        false
    }
}

fn enrich_remote(dependency: &mut Dependency, remote_indexes: &RemoteIndexes<'_>) -> bool {
    let Some(requirement) = canonical_http_url(&dependency.requirement) else {
        return false;
    };
    let Some(integrity) = remote_indexes.integrity_for(&requirement) else {
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
    let Some(mapping) = registry_specifier(
        specifiers,
        &dependency.requirement,
        &normalized_requirement,
        "npm:",
    ) else {
        return false;
    };
    let locked = mapping.locked;
    let normalized_locked = normalize_npm_subpath(locked);
    let locked_key = normalized_locked.strip_prefix("npm:").unwrap_or(locked);
    let resolved = locked_key
        .strip_prefix(name)
        .and_then(|suffix| suffix.strip_prefix('@'))
        .unwrap_or(locked);
    if resolved.is_empty() || !locked_version_compatible(specifier, name, resolved, mapping.exact) {
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
    let normalized_requirement = normalize_jsr_subpath(&dependency.requirement);
    let Some(mapping) = specifiers(lockfile, version).and_then(|specifiers| {
        registry_specifier(
            specifiers,
            &dependency.requirement,
            &normalized_requirement,
            "jsr:",
        )
    }) else {
        return false;
    };
    let locked = mapping.locked;
    let Some(package) = jsr_package_name(&normalized_requirement) else {
        return false;
    };
    let locked_key = locked.strip_prefix("jsr:").unwrap_or(locked);
    let resolved = locked_key
        .strip_prefix(package)
        .and_then(|suffix| suffix.strip_prefix('@'))
        .unwrap_or(locked);
    if resolved.is_empty()
        || !locked_version_compatible(
            normalized_requirement
                .strip_prefix("jsr:")
                .unwrap_or(&normalized_requirement),
            package,
            resolved,
            false,
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

struct RemoteIndexes<'a> {
    integrities: HashMap<String, &'a str>,
    redirects: HashMap<String, &'a str>,
    max_redirect_hops: usize,
}

impl<'a> RemoteIndexes<'a> {
    fn new(
        path: &Path,
        lockfile: &'a JsonValue,
        version: LockVersion,
        max_redirect_hops: usize,
    ) -> Result<Self> {
        let remote = if version == LockVersion::Legacy {
            Some(lockfile)
        } else {
            lockfile.get("remote")
        };
        let integrities = canonical_string_entries(path, remote, "Deno lockfile remote")?;
        let redirects = if version == LockVersion::V5 {
            canonical_string_entries(path, lockfile.get("redirects"), "Deno lockfile redirects")?
        } else {
            HashMap::new()
        };
        Ok(Self {
            integrities,
            redirects,
            max_redirect_hops,
        })
    }

    fn integrity_for(&self, requirement: &str) -> Option<&'a str> {
        let mut url = requirement.to_owned();
        let mut visited = HashSet::new();
        for hops in 0..=self.max_redirect_hops {
            if !visited.insert(url.clone()) {
                return None;
            }
            if let Some(integrity) = self.integrities.get(&url) {
                return Some(integrity);
            }
            if hops == self.max_redirect_hops {
                return None;
            }
            url = canonical_http_url(self.redirects.get(&url)?)?;
        }
        None
    }
}

fn canonical_string_entries<'a>(
    path: &Path,
    value: Option<&'a JsonValue>,
    context: &str,
) -> Result<HashMap<String, &'a str>> {
    let Some(value) = value else {
        return Ok(HashMap::new());
    };
    let entries = value
        .as_object()
        .ok_or_else(|| manifest_error(path, format!("{context} must be an object")))?;
    let mut indexed = HashMap::new();
    for (url, value) in entries {
        let canonical = canonical_http_url(url)
            .ok_or_else(|| manifest_error(path, format!("{context} contains invalid URL {url}")))?;
        let value = value.as_str().ok_or_else(|| {
            manifest_error(path, format!("{context} entry {url} must be a string"))
        })?;
        if let Some(previous) = indexed.insert(canonical.clone(), value)
            && previous != value
        {
            return Err(manifest_error(
                path,
                format!("{context} contains conflicting entries for canonical URL {canonical}"),
            ));
        }
    }
    Ok(indexed)
}

struct RegistrySpecifier<'a> {
    locked: &'a str,
    exact: bool,
}

fn registry_specifier<'a>(
    specifiers: &'a JsonValue,
    declared: &str,
    normalized: &str,
    scheme: &str,
) -> Option<RegistrySpecifier<'a>> {
    let exact = specifiers
        .get(declared)
        .or_else(|| specifiers.get(normalized))
        .or_else(|| specifiers.get(normalized.strip_prefix(scheme).unwrap_or(normalized)))
        .and_then(JsonValue::as_str);
    if let Some(locked) = exact {
        return Some(RegistrySpecifier {
            locked,
            exact: true,
        });
    }
    unique_normalized_specifier(specifiers, normalized, scheme).map(|locked| RegistrySpecifier {
        locked,
        exact: false,
    })
}

fn unique_normalized_specifier<'a>(
    specifiers: &'a JsonValue,
    normalized: &str,
    scheme: &str,
) -> Option<&'a str> {
    specifiers
        .as_object()?
        .iter()
        .filter_map(|(specifier, locked)| {
            (normalize_registry_subpath(specifier, scheme) == normalized)
                .then(|| locked.as_str())
                .flatten()
        })
        .try_fold(None, |candidate, locked| match candidate {
            None => Some(Some(locked)),
            Some(_) => None,
        })
        .flatten()
}

fn normalize_registry_subpath(requirement: &str, scheme: &str) -> String {
    match scheme {
        "npm:" => normalize_npm_subpath(requirement),
        "jsr:" => normalize_jsr_subpath(requirement),
        _ => requirement.to_owned(),
    }
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn locked_version_compatible(
    specifier: &str,
    package: &str,
    resolved: &str,
    exact_mapping: bool,
) -> bool {
    let Ok(version) = NpmVersion::from_str(resolved) else {
        return false;
    };
    let Some(requirement) = specifier
        .strip_prefix(package)
        .and_then(|suffix| suffix.strip_prefix('@'))
    else {
        return true;
    };
    match NpmRange::from_str(requirement) {
        Ok(range) => range.satisfies(&version),
        Err(_) => exact_mapping && is_npm_dist_tag(requirement),
    }
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
