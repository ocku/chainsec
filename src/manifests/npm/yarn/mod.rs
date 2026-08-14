use std::{collections::HashMap, path::Path, str::FromStr};

use node_semver::{Range as NpmRange, Version as NpmVersion};
use serde_json::Value as JsonValue;

use crate::manifests::{
    npm::{github_archive_matches, local_source_url, matching_github_archive},
    shared::{
        github_archive, manifest_error, optional_json_string, parse_bounded_yaml_json, read,
        strip_url_fragment,
    },
};
use crate::{
    error::Result,
    model::{Dependency, canonical_http_url},
};

pub(super) fn enrich(path: &Path, dependencies: &mut [Dependency]) -> Result<()> {
    let lockfile = lockfile_entries(path)?;
    for dependency in dependencies {
        let Some(entry) = find_entry(&lockfile, dependency) else {
            continue;
        };
        enrich_dependency(dependency, entry, path);
    }
    Ok(())
}

struct YarnLockfile {
    entries: Vec<(String, JsonValue)>,
    selectors: HashMap<String, usize>,
}

fn lockfile_entries(path: &Path) -> Result<YarnLockfile> {
    let text = read(path)?;
    let berry = is_berry(&text);
    let normalized = if berry {
        text
    } else {
        normalize_classic(&text)
    };
    let value = parse_bounded_yaml_json(path, &normalized)?;
    let JsonValue::Object(entries) = value else {
        return Err(manifest_error(path, "yarn.lock root must be a mapping"));
    };
    if berry {
        validate_berry_version(path, &entries)?;
    }
    let entries = entries
        .into_iter()
        .filter(|(key, _)| key != "__metadata")
        .collect::<Vec<_>>();
    for (selector, entry) in &entries {
        let entry = entry.as_object().ok_or_else(|| {
            manifest_error(
                path,
                format!("Yarn lock entry {selector} must be an object"),
            )
        })?;
        for field in ["version", "resolved", "resolution", "integrity", "checksum"] {
            optional_json_string(path, entry, field, &format!("Yarn lock entry {selector}"))?;
        }
    }
    let mut selectors = HashMap::new();
    for (entry_index, (key, _)) in entries.iter().enumerate() {
        for selector in std::iter::once(key.trim().trim_matches('"')).chain(selectors_in_key(key)) {
            if let Some(previous) = selectors.insert(selector.to_owned(), entry_index)
                && previous != entry_index
            {
                return Err(manifest_error(
                    path,
                    format!("Yarn selector {selector} maps to multiple lockfile entries"),
                ));
            }
        }
    }
    Ok(YarnLockfile { entries, selectors })
}

fn is_berry(text: &str) -> bool {
    text.lines()
        .any(|line| line.trim_start().starts_with("__metadata:"))
}

fn validate_berry_version(path: &Path, entries: &serde_json::Map<String, JsonValue>) -> Result<()> {
    let version = entries
        .get("__metadata")
        .and_then(|metadata| metadata.get("version"))
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| manifest_error(path, "Yarn Berry metadata version must be an integer"))?;
    if matches!(version, 4..=8) {
        Ok(())
    } else {
        Err(manifest_error(
            path,
            format!("unsupported Yarn Berry lockfile version {version}"),
        ))
    }
}

fn selectors_in_key(key: &str) -> impl Iterator<Item = &str> {
    key.split(", ")
        .map(|selector| selector.trim().trim_matches('"'))
}

fn find_entry<'a>(lockfile: &'a YarnLockfile, dependency: &Dependency) -> Option<&'a JsonValue> {
    let selector = dependency_selector(dependency);
    let berry_selector = format!("{}@npm:{}", dependency.name, dependency.requirement);
    [selector, berry_selector].into_iter().find_map(|selector| {
        let entry_index = *lockfile.selectors.get(&selector)?;
        let (_, entry) = lockfile.entries.get(entry_index)?;
        locked_alias_compatible(dependency, entry).then_some(entry)
    })
}

fn dependency_selector(dependency: &Dependency) -> String {
    format!("{}@{}", dependency.name, dependency.requirement)
}

fn enrich_dependency(dependency: &mut Dependency, entry: &JsonValue, path: &Path) {
    let resolved = entry.get("resolved").and_then(JsonValue::as_str);
    let resolution = entry.get("resolution").and_then(JsonValue::as_str);
    if let Some(reference) = local_resolution(resolved, resolution) {
        let Some(source_url) = local_source_url(path, reference) else {
            return;
        };
        dependency.resolved_version = entry
            .get("version")
            .and_then(JsonValue::as_str)
            .map(str::to_owned);
        dependency.source_url = Some(source_url);
        dependency.lockfile = Some(path.to_owned());
        return;
    }

    if !locked_version_compatible(dependency, entry)
        || !github_archive_matches(dependency, resolved)
    {
        return;
    }

    dependency.lockfile = Some(path.to_owned());
    if let Some((archive, commit)) = resolved
        .and_then(github_archive)
        .or_else(|| matching_github_archive(dependency, resolved))
    {
        dependency.resolved_version = Some(commit);
        dependency.source_url = Some(archive);
        return;
    }
    dependency.resolved_version = entry
        .get("version")
        .and_then(JsonValue::as_str)
        .map(str::to_owned);
    dependency.source_url = resolved
        .and_then(canonical_http_url)
        .as_deref()
        .map(strip_url_fragment);
    dependency.integrity = entry
        .get("integrity")
        .and_then(JsonValue::as_str)
        .map(str::to_owned);

    // Berry checksums cover Yarn's normalized cache ZIP, not the npm tarball.
    // Its npm resolution still pins an exact registry release, whose tarball
    // integrity is retrieved over the configured registry connection later.
    dependency.registry_integrity_required = dependency.integrity.is_none()
        && entry
            .get("resolution")
            .and_then(JsonValue::as_str)
            .and_then(|value| value.rsplit_once("@npm:"))
            .is_some_and(|(_, version)| dependency.resolved_version.as_deref() == Some(version));
}

fn local_resolution<'a>(resolved: Option<&'a str>, resolution: Option<&'a str>) -> Option<&'a str> {
    resolved
        .filter(|value| {
            ["file:", "link:", "portal:", "workspace:"]
                .into_iter()
                .any(|prefix| value.starts_with(prefix))
        })
        .or_else(|| {
            let resolution = resolution?;
            let (_, reference) = resolution.rsplit_once('@')?;
            ["file:", "link:", "portal:", "workspace:"]
                .into_iter()
                .any(|prefix| reference.starts_with(prefix))
                .then_some(reference)
        })
}

fn locked_alias_compatible(dependency: &Dependency, entry: &JsonValue) -> bool {
    let Some(alias) = dependency.requirement.strip_prefix("npm:") else {
        return true;
    };
    let Some((target, requirement)) = parse_alias(alias) else {
        return false;
    };
    let Some(version) = entry.get("version").and_then(JsonValue::as_str) else {
        return false;
    };
    let Ok(range) = NpmRange::from_str(requirement) else {
        return false;
    };
    let Ok(version) = NpmVersion::from_str(version) else {
        return false;
    };
    if !range.satisfies(&version) {
        return false;
    }

    entry
        .get("resolution")
        .map(|resolution| {
            resolution
                .as_str()
                .and_then(|resolution| resolution.rsplit_once("@npm:"))
                .is_some_and(|(locked_target, locked_version)| {
                    locked_target == target
                        && NpmVersion::from_str(locked_version).is_ok_and(|locked_version| {
                            locked_version == version && range.satisfies(&locked_version)
                        })
                })
        })
        .unwrap_or(true)
}

fn parse_alias(alias: &str) -> Option<(&str, &str)> {
    let (target, requirement) = alias.rsplit_once('@')?;
    (!target.is_empty() && !requirement.is_empty() && valid_package_name(target))
        .then_some((target, requirement))
}

fn valid_package_name(name: &str) -> bool {
    if let Some(scoped) = name.strip_prefix('@') {
        let Some((scope, package)) = scoped.split_once('/') else {
            return false;
        };
        !scope.is_empty() && !package.is_empty() && !package.contains('/')
    } else {
        !name.is_empty() && !name.contains('@') && !name.contains('/')
    }
}

fn locked_version_compatible(dependency: &Dependency, entry: &JsonValue) -> bool {
    let requirement = dependency
        .requirement
        .strip_prefix("npm:")
        .and_then(parse_alias)
        .map(|(_, requirement)| requirement)
        .unwrap_or(&dependency.requirement);
    let Ok(range) = NpmRange::from_str(requirement) else {
        return !dependency.requirement.starts_with("npm:");
    };
    entry
        .get("version")
        .and_then(JsonValue::as_str)
        .and_then(|version| NpmVersion::from_str(version).ok())
        .is_some_and(|version| range.satisfies(&version))
}

fn normalize_classic(text: &str) -> String {
    let mut output = String::with_capacity(text.len() + 64);
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.ends_with(':')
            || trimmed.contains(": ")
        {
            output.push_str(line);
        } else if let Some((key, value)) = trimmed.split_once(char::is_whitespace) {
            output.push_str(&line[..line.len() - trimmed.len()]);
            output.push_str(key);
            output.push_str(": ");
            output.push_str(value.trim_start());
        } else {
            output.push_str(line);
        }
        output.push('\n');
    }
    output
}

#[cfg(test)]
mod tests;
