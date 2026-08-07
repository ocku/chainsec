use std::path::{Path, PathBuf};

use serde_json::Value as JsonValue;

use super::shared::{manifest_error, read};
use crate::{
    error::Result,
    model::{Dependency, Ecosystem},
};

pub(super) fn parse(path: &Path) -> Result<Vec<Dependency>> {
    let clean = strip_jsonc(&read(path)?).map_err(|message| manifest_error(path, message))?;
    let value: JsonValue =
        serde_json::from_str(&clean).map_err(|error| manifest_error(path, error))?;
    let mut result = Vec::new();
    if let Some(imports) = value.get("imports") {
        let entries = imports
            .as_object()
            .ok_or_else(|| manifest_error(path, "Deno manifest imports must be an object"))?;
        collect_entries(path, entries, &mut result)?;
    }
    if let Some(scopes) = value.get("scopes") {
        let scopes = scopes
            .as_object()
            .ok_or_else(|| manifest_error(path, "Deno manifest scopes must be an object"))?;
        for (scope, entries) in scopes {
            let entries = entries.as_object().ok_or_else(|| {
                manifest_error(
                    path,
                    format!("Deno manifest scope {scope} must be an object"),
                )
            })?;
            collect_entries(path, entries, &mut result)?;
        }
    }
    Ok(result)
}

fn collect_entries(
    path: &Path,
    entries: &serde_json::Map<String, JsonValue>,
    result: &mut Vec<Dependency>,
) -> Result<()> {
    for (name, value) in entries {
        let requirement = value.as_str().ok_or_else(|| {
            manifest_error(path, format!("Deno manifest entry {name} must be a string"))
        })?;
        let mut dependency = Dependency::declared(Ecosystem::Deno, name, requirement);
        if requirement.starts_with("http://") || requirement.starts_with("https://") {
            dependency.source_url = Some(requirement.to_owned());
            dependency.resolved_version = Some(requirement.to_owned());
        }
        result.push(dependency);
    }
    Ok(())
}

pub(super) fn enrich(
    root: &Path,
    dependencies: &mut [Dependency],
    lockfiles: &mut Vec<PathBuf>,
) -> Result<()> {
    let path = root.join("deno.lock");
    if !path.is_file() {
        return Ok(());
    }
    let value: JsonValue =
        serde_json::from_str(&read(&path)?).map_err(|error| manifest_error(&path, error))?;
    let version = value
        .get("version")
        .and_then(JsonValue::as_str)
        .unwrap_or("1");
    if !matches!(version, "1" | "2" | "3" | "4") {
        return Err(manifest_error(
            &path,
            format!("unsupported deno lockfile version {version}"),
        ));
    }
    for dependency in dependencies {
        let requirement = dependency.requirement.as_str();
        let integrity = if requirement.starts_with("http") {
            value
                .get("remote")
                .and_then(|v| v.get(requirement))
                .and_then(JsonValue::as_str)
        } else if let Some(spec) = requirement.strip_prefix("npm:") {
            let resolved = value
                .get("specifiers")
                .and_then(|v| v.get(requirement))
                .and_then(JsonValue::as_str)
                .unwrap_or_else(|| spec.rsplit_once('@').map_or(spec, |(_, version)| version));
            dependency.resolved_version = Some(resolved.to_owned());
            let name = spec.rsplit_once('@').map_or(spec, |(name, _)| name);
            value
                .get("npm")
                .and_then(|v| v.get(format!("{name}@{resolved}")))
                .and_then(|v| v.get("integrity"))
                .and_then(JsonValue::as_str)
        } else if requirement.starts_with("jsr:") {
            let resolved = value
                .get("specifiers")
                .and_then(|v| v.get(requirement))
                .and_then(JsonValue::as_str);
            if let Some(resolved) = resolved {
                dependency.resolved_version = Some(resolved.to_owned());
                if let Some(package) = jsr_package_name(requirement) {
                    let package_key = format!("{package}@{resolved}");
                    let locked_integrity = value
                        .get("jsr")
                        .and_then(|v| v.get(&package_key))
                        .and_then(|v| v.get("integrity"))
                        .and_then(JsonValue::as_str)
                        .filter(|value| {
                            value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                        });
                    if let Some(locked_integrity) = locked_integrity {
                        dependency.integrity = Some(format!("sha256:{locked_integrity}"));
                        dependency.source_url =
                            Some(format!("https://jsr.io/{package}/{resolved}_meta.json"));
                    }
                }
            }
            None
        } else {
            None
        };
        if let Some(integrity) = integrity {
            dependency.integrity = Some(integrity.to_owned());
        }
        if dependency.resolved_version.is_none() && requirement.starts_with("http") {
            dependency.resolved_version = Some(requirement.to_owned());
        }
        dependency.lockfile = Some(path.clone());
    }
    lockfiles.push(path);
    Ok(())
}

fn jsr_package_name(requirement: &str) -> Option<&str> {
    let specifier = requirement.strip_prefix("jsr:")?;
    let (package, _) = specifier.rsplit_once('@')?;
    (!package.is_empty()).then_some(package)
}

pub(super) fn strip_jsonc(input: &str) -> std::result::Result<String, String> {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(character) = chars.next() {
        if in_string {
            output.push(character);
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }
        if character == '"' {
            in_string = true;
            output.push(character);
            continue;
        }
        if character == '/' && chars.peek() == Some(&'/') {
            chars.next();
            for next in chars.by_ref() {
                if next == '\n' {
                    output.push('\n');
                    break;
                }
            }
            continue;
        }
        if character == '/' && chars.peek() == Some(&'*') {
            chars.next();
            let mut closed = false;
            while let Some(next) = chars.next() {
                if next == '\n' {
                    output.push('\n');
                }
                if next == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    closed = true;
                    break;
                }
            }
            if !closed {
                return Err("unterminated block comment".to_owned());
            }
            continue;
        }
        output.push(character);
    }
    if in_string {
        return Err("unterminated string".to_owned());
    }
    Ok(output)
}
