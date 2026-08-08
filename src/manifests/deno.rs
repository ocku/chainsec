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
    let lockfile: JsonValue =
        serde_json::from_str(&read(&path)?).map_err(|error| manifest_error(&path, error))?;
    validate_lockfile_version(&path, &lockfile)?;

    for dependency in dependencies {
        enrich_dependency(&lockfile, dependency);
        dependency.lockfile = Some(path.clone());
    }
    lockfiles.push(path);
    Ok(())
}

fn validate_lockfile_version(path: &Path, lockfile: &JsonValue) -> Result<()> {
    let version = lockfile
        .get("version")
        .and_then(JsonValue::as_str)
        .unwrap_or("1");
    if matches!(version, "1" | "2" | "3" | "4" | "5") {
        return Ok(());
    }
    Err(manifest_error(
        path,
        format!("unsupported deno lockfile version {version}"),
    ))
}

fn enrich_dependency(lockfile: &JsonValue, dependency: &mut Dependency) {
    if dependency.requirement.starts_with("http") {
        enrich_remote(lockfile, dependency);
    } else if dependency.requirement.starts_with("npm:") {
        enrich_npm(lockfile, dependency);
    } else if dependency.requirement.starts_with("jsr:") {
        enrich_jsr(lockfile, dependency);
    }
}

fn enrich_remote(lockfile: &JsonValue, dependency: &mut Dependency) {
    dependency.integrity = lockfile
        .get("remote")
        .and_then(|remote| remote.get(&dependency.requirement))
        .and_then(JsonValue::as_str)
        .map(str::to_owned);
    dependency
        .resolved_version
        .get_or_insert_with(|| dependency.requirement.clone());
}

fn enrich_npm(lockfile: &JsonValue, dependency: &mut Dependency) {
    let specifier = dependency
        .requirement
        .strip_prefix("npm:")
        .expect("npm dependencies must have an npm: prefix")
        .to_owned();
    let resolved = lockfile
        .get("specifiers")
        .and_then(|specifiers| specifiers.get(&dependency.requirement))
        .and_then(JsonValue::as_str)
        .unwrap_or_else(|| {
            specifier
                .rsplit_once('@')
                .map_or(&specifier, |(_, version)| version)
        });
    dependency.resolved_version = Some(resolved.to_owned());

    let name = specifier
        .rsplit_once('@')
        .map_or(specifier.as_str(), |(name, _)| name);
    dependency.integrity = lockfile
        .get("npm")
        .and_then(|packages| packages.get(format!("{name}@{resolved}")))
        .and_then(|package| package.get("integrity"))
        .and_then(JsonValue::as_str)
        .map(str::to_owned);
}

fn enrich_jsr(lockfile: &JsonValue, dependency: &mut Dependency) {
    let Some(resolved) = lockfile
        .get("specifiers")
        .and_then(|specifiers| specifiers.get(&dependency.requirement))
        .and_then(JsonValue::as_str)
    else {
        return;
    };
    dependency.resolved_version = Some(resolved.to_owned());

    let Some(package) = jsr_package_name(&dependency.requirement) else {
        return;
    };
    let package_key = format!("{package}@{resolved}");
    let integrity = lockfile
        .get("jsr")
        .and_then(|packages| packages.get(&package_key))
        .and_then(|package| package.get("integrity"))
        .and_then(JsonValue::as_str)
        .filter(|integrity| is_sha256_digest(integrity));
    let Some(integrity) = integrity else {
        return;
    };

    dependency.integrity = Some(format!("sha256:{integrity}"));
    dependency.source_url = Some(format!("https://jsr.io/{package}/{resolved}_meta.json"));
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
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
