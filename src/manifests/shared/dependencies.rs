use std::{collections::HashMap, path::Path};

use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::error::{Error, Result};

pub(in crate::manifests) fn is_sha256_integrity(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

pub(in crate::manifests) fn is_npm_dist_tag(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// Collects package dependencies using npm's cross-section precedence.
pub(in crate::manifests) fn package_json_dependencies(
    path: &Path,
    package: &JsonMap<String, JsonValue>,
    max_packages: usize,
) -> Result<HashMap<String, String>> {
    let mut by_name = HashMap::new();
    // Peer dependencies are a fallback only. Development dependencies are included
    // by default, while normal and optional dependencies take precedence, matching
    // npm's duplicate-section semantics.
    for section in [
        "peerDependencies",
        "devDependencies",
        "dependencies",
        "optionalDependencies",
    ] {
        let Some(value) = package.get(section) else {
            continue;
        };
        let entries = value
            .as_object()
            .ok_or_else(|| super::manifest_error(path, format!("{section} must be an object")))?;
        for (name, value) in entries {
            let requirement = value.as_str().ok_or_else(|| {
                super::manifest_error(path, format!("{section}.{name} must be a string"))
            })?;
            let is_new = !by_name.contains_key(name);
            if is_new && by_name.len() >= max_packages {
                return Err(Error::LimitExceeded {
                    resource: "manifest dependencies".to_owned(),
                    limit: u64::try_from(max_packages).unwrap_or(u64::MAX),
                });
            }
            by_name.insert(name.clone(), requirement.to_owned());
        }
    }
    Ok(by_name)
}

pub(in crate::manifests) fn strip_url_fragment(url: &str) -> String {
    url.split('#').next().unwrap_or(url).to_owned()
}

pub(in crate::manifests) fn github_archive(reference: &str) -> Option<(String, String)> {
    let reference = reference
        .split_once(" @ ")
        .map_or(reference.trim(), |(_, source)| source.trim());
    let (repository, commit) = reference
        .rsplit_once('#')
        .or_else(|| reference.rsplit_once(".git@"))?;
    if commit.len() != 40 || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let repository = repository.strip_prefix("git+").unwrap_or(repository);
    let repository = repository
        .strip_prefix("https://github.com/")
        .or_else(|| repository.strip_prefix("ssh://git@github.com/"))
        .or_else(|| repository.strip_prefix("git://github.com/"))
        .or_else(|| repository.strip_prefix("git@github.com:"))
        .or_else(|| repository.strip_prefix("github:"))
        .unwrap_or(repository);
    let repository = repository.strip_suffix(".git").unwrap_or(repository);
    let mut parts = repository.split('/');
    let owner = parts.next()?;
    let name = parts.next()?;
    if parts.next().is_some()
        || owner.is_empty()
        || name.is_empty()
        || !owner
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return None;
    }
    let commit = commit.to_ascii_lowercase();
    Some((
        format!("https://codeload.github.com/{owner}/{name}/tar.gz/{commit}"),
        commit,
    ))
}
