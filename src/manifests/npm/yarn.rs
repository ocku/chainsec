use std::path::Path;

use serde_json::Value as JsonValue;

use super::super::shared::{github_archive, manifest_error, read, strip_url_fragment};
use crate::{error::Result, model::Dependency};

pub(super) fn enrich(path: &Path, dependencies: &mut [Dependency]) -> Result<()> {
    let text = read(path)?;
    let normalized = if text
        .lines()
        .any(|line| line.trim_start().starts_with("__metadata:"))
    {
        text
    } else {
        normalize_classic(&text)
    };
    let yaml: serde_yaml::Value =
        serde_yaml::from_str(&normalized).map_err(|error| manifest_error(path, error))?;
    let value = serde_json::to_value(yaml).map_err(|error| manifest_error(path, error))?;
    let entries = value
        .as_object()
        .ok_or_else(|| manifest_error(path, "yarn.lock root must be a mapping"))?;
    let berry = entries.contains_key("__metadata");
    if berry {
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
    }
    for dependency in dependencies {
        let classic_selector = format!("{}@{}", dependency.name, dependency.requirement);
        let berry_selector = if dependency.requirement.starts_with("npm:") {
            classic_selector.clone()
        } else {
            format!("{}@npm:{}", dependency.name, dependency.requirement)
        };
        let selector = if berry {
            berry_selector.as_str()
        } else {
            classic_selector.as_str()
        };
        let Some(entry) = entries.iter().find_map(|(key, value)| {
            key.split(',')
                .map(|part| part.trim().trim_matches('"'))
                .any(|part| part == selector)
                .then_some(value)
        }) else {
            continue;
        };
        dependency.lockfile = Some(path.to_owned());
        let resolved = entry.get("resolved").and_then(JsonValue::as_str);
        if let Some((archive, commit)) = resolved.and_then(github_archive) {
            dependency.resolved_version = Some(commit);
            dependency.source_url = Some(archive);
            continue;
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
    Ok(())
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
