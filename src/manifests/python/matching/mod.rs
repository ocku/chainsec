use std::{collections::HashMap, path::Path, str::FromStr};

use pep440_rs::{Version, VersionSpecifiers};
use serde_json::Value as JsonValue;
use toml::Value as TomlValue;
use url::Url;

use super::lockfiles::package_string;
use crate::{error::Result, manifests::shared::manifest_error, model::Dependency};

pub(super) type TomlPackageIndex<'a> = HashMap<String, Vec<&'a TomlValue>>;
pub(super) type JsonPackageIndex<'a> = HashMap<String, Vec<&'a JsonValue>>;

pub(super) fn index_toml_packages(packages: &[TomlValue]) -> TomlPackageIndex<'_> {
    let mut index = HashMap::new();
    for package in packages {
        if let Some(name) = package.get("name").and_then(TomlValue::as_str) {
            index
                .entry(normalize(name))
                .or_insert_with(Vec::new)
                .push(package);
        }
    }
    index
}

fn select_toml_lock_entry<'a>(
    path: &Path,
    dependency: &Dependency,
    candidates: &[&'a TomlValue],
) -> Result<Option<&'a TomlValue>> {
    let specifiers = dependency_specifiers(path, dependency)?;
    let compatible = candidates
        .iter()
        .copied()
        .filter(|package| {
            lock_version_compatible(
                dependency,
                specifiers.as_ref(),
                package_string(package, "version").as_deref(),
            )
        })
        .filter(|package| toml_source_compatible(dependency, package))
        .collect::<Vec<_>>();
    select_unique(path, dependency, candidates.len(), compatible)
}

pub(super) fn select_json_lock_entry<'a>(
    path: &Path,
    dependency: &Dependency,
    candidates: &[&'a JsonValue],
) -> Result<Option<&'a JsonValue>> {
    let specifiers = dependency_specifiers(path, dependency)?;
    let compatible = candidates
        .iter()
        .copied()
        .filter(|entry| {
            lock_version_compatible(
                dependency,
                specifiers.as_ref(),
                entry
                    .get("version")
                    .and_then(JsonValue::as_str)
                    .map(|version| version.trim_start_matches("==")),
            )
        })
        .filter(|entry| json_source_compatible(dependency, entry))
        .collect::<Vec<_>>();
    select_unique(path, dependency, candidates.len(), compatible)
}

fn select_unique<'a, T>(
    path: &Path,
    dependency: &Dependency,
    named_count: usize,
    compatible: Vec<&'a T>,
) -> Result<Option<&'a T>> {
    match compatible.as_slice() {
        [] if named_count == 0 => Ok(None),
        [] => Err(manifest_error(
            path,
            format!(
                "no lock record for {} is compatible with its declared requirement or source",
                dependency.name
            ),
        )),
        [record] => Ok(Some(*record)),
        _ => Err(manifest_error(
            path,
            format!(
                "ambiguous lock records for {}: {} compatible records",
                dependency.name,
                compatible.len()
            ),
        )),
    }
}

fn lock_version_compatible(
    dependency: &Dependency,
    specifiers: Option<&VersionSpecifiers>,
    version: Option<&str>,
) -> bool {
    let Some(version) = version.and_then(|version| Version::from_str(version).ok()) else {
        return false;
    };

    if dependency.source_url.is_some() || dependency.is_pinned_github() {
        return true;
    }
    let Some(specifiers) = specifiers else {
        return true;
    };
    specifiers.contains(&version)
}

fn dependency_specifiers(
    path: &Path,
    dependency: &Dependency,
) -> Result<Option<VersionSpecifiers>> {
    let requirement = dependency
        .requirement
        .split(';')
        .next()
        .unwrap_or_default()
        .trim();
    let mut constraint = requirement
        .strip_prefix(&dependency.name)
        .unwrap_or(requirement)
        .trim();
    if constraint.starts_with('[') {
        constraint = constraint
            .split_once(']')
            .map(|(_, suffix)| suffix.trim())
            .ok_or_else(|| {
                manifest_error(
                    path,
                    format!("Python dependency {} has malformed extras", dependency.name),
                )
            })?;
    }
    if constraint.is_empty()
        || constraint == "*"
        || constraint.starts_with('@')
        || constraint.starts_with("file:")
        || constraint.starts_with("git+")
    {
        return Ok(None);
    }
    VersionSpecifiers::from_str(constraint)
        .map(Some)
        .map_err(|error| {
            manifest_error(
                path,
                format!(
                    "Python dependency {} has an invalid version constraint: {error}",
                    dependency.name
                ),
            )
        })
}

fn toml_source_compatible(dependency: &Dependency, package: &TomlValue) -> bool {
    if dependency.is_pinned_github() && package.get("source").is_none() {
        return true;
    }
    let Some(expected) = dependency.source_url.as_deref() else {
        return true;
    };
    let source = package.get("source");

    if toml_git_source(source) {
        let Some((expected_source, expected_revision)) = git_identity(expected)
            .or_else(|| git_identity(&dependency.requirement))
            .or_else(|| github_archive_identity(expected))
        else {
            return false;
        };
        let Some((locked_source, locked_revision)) = toml_git_identity(source) else {
            return false;
        };
        return expected_source == locked_source
            && revisions_equal(&expected_revision, &locked_revision);
    }

    if toml_directory_source(source) {
        let expected = expected.strip_prefix("file:").unwrap_or(expected);
        return toml_source_strings(source, ["directory", "path", "url"])
            .any(|candidate| candidate == expected);
    }

    toml_source_strings(source, ["url"])
        .chain(package.get("url").and_then(TomlValue::as_str))
        .any(|candidate| candidate == expected)
}

fn toml_git_source(source: Option<&TomlValue>) -> bool {
    source.is_some_and(|source| {
        source.get("type").and_then(TomlValue::as_str) == Some("git")
            || source.get("git").and_then(TomlValue::as_str).is_some()
    })
}

fn toml_directory_source(source: Option<&TomlValue>) -> bool {
    source.is_some_and(|source| {
        matches!(
            source.get("type").and_then(TomlValue::as_str),
            Some("directory") | Some("path")
        ) || source
            .get("directory")
            .and_then(TomlValue::as_str)
            .is_some()
            || source.get("path").and_then(TomlValue::as_str).is_some()
    })
}

fn toml_git_identity(source: Option<&TomlValue>) -> Option<(Url, String)> {
    let source = source?;
    let url = toml_source_strings(Some(source), ["git", "url"]).next()?;
    let resolved = toml_source_strings(
        Some(source),
        [
            "resolved_reference",
            "resolved-revision",
            "resolved_revision",
        ],
    )
    .find(|revision| immutable_revision(revision));
    match resolved {
        Some(revision) => Some((canonical_git_url(url)?, revision.to_owned())),
        None => git_identity(url).filter(|(_, revision)| immutable_revision(revision)),
    }
}

fn toml_source_strings<'a>(
    source: Option<&'a TomlValue>,
    keys: impl IntoIterator<Item = &'a str>,
) -> impl Iterator<Item = &'a str> {
    keys.into_iter().filter_map(move |key| {
        source
            .and_then(|source| source.get(key))
            .and_then(TomlValue::as_str)
    })
}

fn json_source_compatible(dependency: &Dependency, entry: &JsonValue) -> bool {
    if dependency.is_pinned_github() {
        return true;
    }
    let Some(expected) = dependency.source_url.as_deref() else {
        return true;
    };
    if let Some(git) = entry.get("git").and_then(JsonValue::as_str) {
        let Some((expected_source, expected_revision)) =
            git_identity(expected).or_else(|| git_identity(&dependency.requirement))
        else {
            return false;
        };
        let Some(locked_source) = canonical_git_url(git) else {
            return false;
        };
        return expected_source == locked_source
            && entry
                .get("ref")
                .and_then(JsonValue::as_str)
                .is_some_and(|revision| revisions_equal(&expected_revision, revision));
    }
    ["file", "path"]
        .into_iter()
        .filter_map(|key| entry.get(key).and_then(JsonValue::as_str))
        .any(|candidate| candidate == expected)
}

fn git_identity(value: &str) -> Option<(Url, String)> {
    let value = value
        .find("git+")
        .map_or(value, |position| &value[position + "git+".len()..]);
    let (source, fragment) = value
        .split_once('#')
        .map_or((value, None), |(source, fragment)| (source, Some(fragment)));
    let (source, revision) = source
        .rsplit_once('@')
        .or_else(|| fragment.map(|revision| (source, revision)))?;
    if revision.is_empty() {
        return None;
    }
    Some((canonical_git_url(source)?, revision.to_owned()))
}

fn github_archive_identity(value: &str) -> Option<(Url, String)> {
    let url = Url::parse(value).ok()?;
    if url.host_str() != Some("codeload.github.com") {
        return None;
    }
    let mut segments = url.path_segments()?;
    let owner = segments.next()?;
    let repository = segments.next()?;
    if segments.next()? != "tar.gz" {
        return None;
    }
    let revision = segments.next()?;
    if segments.next().is_some() || !immutable_revision(revision) {
        return None;
    }
    canonical_git_url(&format!("https://github.com/{owner}/{repository}.git"))
        .map(|source| (source, revision.to_owned()))
}

fn canonical_git_url(value: &str) -> Option<Url> {
    let mut url = Url::parse(value.strip_prefix("git+").unwrap_or(value)).ok()?;
    url.set_query(None);
    url.set_fragment(None);
    Some(url)
}

fn immutable_revision(revision: &str) -> bool {
    revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn revisions_equal(expected: &str, locked: &str) -> bool {
    immutable_revision(expected)
        && immutable_revision(locked)
        && expected.eq_ignore_ascii_case(locked)
}

pub(super) fn find_package<'a>(
    path: &Path,
    index: &'a TomlPackageIndex<'a>,
    dependency: &Dependency,
) -> Result<Option<&'a TomlValue>> {
    let normalized_name = normalize(&dependency.name);
    let named = index
        .get(&normalized_name)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    select_toml_lock_entry(path, dependency, named)
}

pub(super) fn find_json_package<'a>(
    path: &Path,
    index: &'a JsonPackageIndex<'a>,
    dependency: &Dependency,
) -> Result<Option<&'a JsonValue>> {
    let normalized_name = normalize(&dependency.name);
    let named = index
        .get(&normalized_name)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    select_json_lock_entry(path, dependency, named)
}

pub(super) fn normalize(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    let mut separator = false;
    for character in name.chars() {
        if matches!(character, '-' | '_' | '.') {
            if !separator {
                normalized.push('-');
                separator = true;
            }
        } else {
            normalized.extend(character.to_lowercase());
            separator = false;
        }
    }
    normalized
}

#[cfg(test)]
mod tests;
