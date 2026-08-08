use std::path::Path;

use serde_json::Value as JsonValue;

use crate::manifests::shared::{github_archive, manifest_error, read, strip_url_fragment};
use crate::{error::Result, model::Dependency};

pub(super) fn enrich(path: &Path, dependencies: &mut [Dependency]) -> Result<()> {
    let (entries, berry) = lockfile_entries(path)?;
    for dependency in dependencies {
        let Some(entry) = find_entry(&entries, dependency, berry) else {
            continue;
        };
        enrich_dependency(dependency, entry, path, berry);
    }
    Ok(())
}

fn lockfile_entries(path: &Path) -> Result<(serde_json::Map<String, JsonValue>, bool)> {
    let text = read(path)?;
    let normalized = if is_berry(&text) {
        text
    } else {
        normalize_classic(&text)
    };
    let yaml: serde_yaml::Value =
        serde_yaml::from_str(&normalized).map_err(|error| manifest_error(path, error))?;
    let value = serde_json::to_value(yaml).map_err(|error| manifest_error(path, error))?;
    let JsonValue::Object(entries) = value else {
        return Err(manifest_error(path, "yarn.lock root must be a mapping"));
    };
    let berry = entries.contains_key("__metadata");
    if berry {
        validate_berry_version(path, &entries)?;
    }
    Ok((entries, berry))
}

fn is_berry(text: &str) -> bool {
    text.lines()
        .any(|line| line.trim_start().starts_with("__metadata:"))
}

fn validate_berry_version(path: &Path, entries: &serde_json::Map<String, JsonValue>) -> Result<()> {
    let version = entries
        .get("__metadata")
        .and_then(|value| value.get("version"))
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| manifest_error(path, "Yarn metadata version must be an integer"))?;
    if !(4..=8).contains(&version) {
        return Err(manifest_error(
            path,
            format!("unsupported Yarn lockfile version {version}"),
        ));
    }
    Ok(())
}

fn find_entry<'a>(
    entries: &'a serde_json::Map<String, JsonValue>,
    dependency: &Dependency,
    berry: bool,
) -> Option<&'a JsonValue> {
    let selector = dependency_selector(dependency, berry);
    entries.iter().find_map(|(key, value)| {
        key.split(',')
            .map(|part| part.trim().trim_matches('"'))
            .any(|part| part == selector)
            .then_some(value)
    })
}

fn dependency_selector(dependency: &Dependency, berry: bool) -> String {
    let selector = format!("{}@{}", dependency.name, dependency.requirement);
    if berry && !dependency.requirement.starts_with("npm:") {
        format!("{}@npm:{}", dependency.name, dependency.requirement)
    } else {
        selector
    }
}

fn enrich_dependency(dependency: &mut Dependency, entry: &JsonValue, path: &Path, berry: bool) {
    dependency.lockfile = Some(path.to_owned());
    let resolved = entry.get("resolved").and_then(JsonValue::as_str);
    if let Some((archive, commit)) = resolved.and_then(github_archive) {
        dependency.resolved_version = Some(commit);
        dependency.source_url = Some(archive);
        return;
    }
    dependency.resolved_version = entry
        .get("version")
        .and_then(JsonValue::as_str)
        .map(str::to_owned);
    if !berry {
        dependency.source_url = resolved
            .filter(|url| url.starts_with("http://") || url.starts_with("https://"))
            .map(strip_url_fragment);
        dependency.integrity = entry
            .get("integrity")
            .and_then(JsonValue::as_str)
            .map(str::to_owned);
    }
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
