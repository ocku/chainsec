use std::{
    env, fs,
    path::{Path, PathBuf},
};

use serde::Deserialize;

use super::repositories::ArtifactoriesConfig;
use crate::app::cli::{OutputFormat, Severity};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::app) struct SuppressionConfig {
    pub(in crate::app) rule: String,
    pub(in crate::app) package: Option<String>,
    pub(in crate::app) reason: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::app) struct FileConfig {
    pub(super) max_package_depth: Option<usize>,
    pub(super) max_packages: Option<usize>,
    pub(super) max_network_requests: Option<usize>,
    pub(super) max_redirect_hops: Option<usize>,
    pub(super) request_timeout_seconds: Option<u64>,
    pub(super) max_acquisition_seconds: Option<u64>,
    pub(super) max_archive_size: Option<u64>,
    pub(super) max_extracted_size: Option<u64>,
    pub(super) max_extracted_files: Option<u64>,
    pub(super) max_file_depth: Option<usize>,
    pub(super) max_manifest_file_size: Option<u64>,
    pub(super) max_source_file_size: Option<u64>,
    pub(super) max_source_files: Option<u64>,
    pub(super) max_findings: Option<u64>,
    pub(super) max_scan_seconds: Option<u64>,
    pub(super) fail_on_parse_error: Option<bool>,
    pub(super) threads: Option<usize>,
    pub(super) cache: Option<PathBuf>,
    pub(super) allow_unlocked: Option<bool>,
    pub(super) trust_local_input: Option<bool>,
    pub(super) allow_insecure_http: Option<bool>,
    pub(super) online: Option<bool>,
    pub(super) allowed_hosts: Option<Vec<String>>,
    pub(super) artifactories: Option<ArtifactoriesConfig>,
    pub(super) rule_packs: Option<Vec<PathBuf>>,
    pub(super) no_default_rules: Option<bool>,
    pub(super) ignored_rules: Option<Vec<String>>,
    pub(super) suppressions: Option<Vec<SuppressionConfig>>,
    pub(super) ignored_packages: Option<Vec<String>>,
    pub(super) ignored_paths: Option<Vec<String>>,
    pub(super) format: Option<OutputFormat>,
    pub(super) fail_on: Option<Severity>,
    pub(super) output: Option<PathBuf>,
}

impl FileConfig {
    /// Overlay repository settings on global settings. `Some` values in
    /// `overriding` replace the corresponding global value.
    fn overlay(self, overriding: Self) -> Self {
        Self {
            max_package_depth: overriding.max_package_depth.or(self.max_package_depth),
            max_packages: overriding.max_packages.or(self.max_packages),
            max_network_requests: overriding
                .max_network_requests
                .or(self.max_network_requests),
            max_redirect_hops: overriding.max_redirect_hops.or(self.max_redirect_hops),
            request_timeout_seconds: overriding
                .request_timeout_seconds
                .or(self.request_timeout_seconds),
            max_acquisition_seconds: overriding
                .max_acquisition_seconds
                .or(self.max_acquisition_seconds),
            max_archive_size: overriding.max_archive_size.or(self.max_archive_size),
            max_extracted_size: overriding.max_extracted_size.or(self.max_extracted_size),
            max_extracted_files: overriding.max_extracted_files.or(self.max_extracted_files),
            max_file_depth: overriding.max_file_depth.or(self.max_file_depth),
            max_manifest_file_size: overriding
                .max_manifest_file_size
                .or(self.max_manifest_file_size),
            max_source_file_size: overriding
                .max_source_file_size
                .or(self.max_source_file_size),
            max_source_files: overriding.max_source_files.or(self.max_source_files),
            max_findings: overriding.max_findings.or(self.max_findings),
            max_scan_seconds: overriding.max_scan_seconds.or(self.max_scan_seconds),
            fail_on_parse_error: overriding.fail_on_parse_error.or(self.fail_on_parse_error),
            threads: overriding.threads.or(self.threads),
            cache: overriding.cache.or(self.cache),
            allow_unlocked: overriding.allow_unlocked.or(self.allow_unlocked),
            trust_local_input: overriding.trust_local_input.or(self.trust_local_input),
            allow_insecure_http: overriding.allow_insecure_http.or(self.allow_insecure_http),
            online: overriding.online.or(self.online),
            allowed_hosts: extend_hosts(self.allowed_hosts, overriding.allowed_hosts),
            artifactories: match (self.artifactories, overriding.artifactories) {
                (Some(global), Some(repository)) => Some(global.overlay(repository)),
                (Some(global), None) => Some(global),
                (None, Some(repository)) => Some(repository),
                (None, None) => None,
            },
            rule_packs: overriding.rule_packs.or(self.rule_packs),
            no_default_rules: overriding.no_default_rules.or(self.no_default_rules),
            ignored_rules: overriding.ignored_rules.or(self.ignored_rules),
            suppressions: overriding.suppressions.or(self.suppressions),
            ignored_packages: overriding.ignored_packages.or(self.ignored_packages),
            ignored_paths: overriding.ignored_paths.or(self.ignored_paths),
            format: overriding.format.or(self.format),
            fail_on: overriding.fail_on.or(self.fail_on),
            output: overriding.output.or(self.output),
        }
    }
}

pub(super) fn extend_hosts(
    base: Option<Vec<String>>,
    extending: Option<Vec<String>>,
) -> Option<Vec<String>> {
    match (base, extending) {
        (Some(mut base), Some(extending)) => {
            for host in extending {
                if !base.contains(&host) {
                    base.push(host);
                }
            }
            Some(base)
        }
        (Some(base), None) => Some(base),
        (None, Some(extending)) => Some(extending),
        (None, None) => None,
    }
}

const INITIAL_CONFIG: &str = r#"# chainsec project configuration
# See https://github.com/ocku/chainsec#project-configuration for all options.
# Command-line options override values in this file.

# Keep dependency traversal bounded. Set to 0 to scan only this project.
max_package_depth = 3
max_packages = 500

# Network access remains disabled unless both options below are configured.
# online = true
# allowed_hosts = ["registry.npmjs.org", "pypi.org", "files.pythonhosted.org"]

# Optional HTTPS repository-manager endpoints. These replace only metadata lookup;
# locked artifact URLs are still honored and integrity-checked, but never receive
# configured credentials. Credentials are read only from explicitly named environment
# variables and require an HTTPS scope.
# [artifactories.npm]
# metadata_base_url = "https://packages.example/npm"
#
# [artifactories.npm.credential]
# scope = "https://packages.example/"
# bearer_token_env = "PACKAGE_REGISTRY_TOKEN"
#
# [artifactories.pypi]
# metadata_base_url = "https://metadata.packages.example/pypi"
# artifact_base_url = "https://artifacts.packages.example/packages"

# Ignore generated or test-only root-project paths. Dependencies are unaffected.
ignored_paths = ["tests/**"]

# Examples:
# ignored_rules = ["network:*"]
# ignored_packages = ["npm:legacy-package@1.2.3"]
# fail_on = "high"
#
# [[suppressions]]
# rule = "network:chainsec.detection.network-request.*"
# package = "npm:telemetry-client@2.1.0"
# reason = "Approved telemetry dependency; tracked in SEC-1234"
"#;

fn config_path(root: &Path) -> Option<PathBuf> {
    let path = root.join("chainsec.toml");
    path.is_file().then_some(path)
}

fn user_config_directory() -> Option<PathBuf> {
    env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .map(|directory| directory.join("chainsec"))
}

fn global_config_path() -> Option<PathBuf> {
    if let Some(directory) = user_config_directory() {
        let config = directory.join("config.toml");
        if config.is_file() {
            return Some(config);
        }

        // Accept the project-style filename as a fallback for existing user setups.
        let legacy_config = directory.join("chainsec.toml");
        if legacy_config.is_file() {
            return Some(legacy_config);
        }
    }

    PathBuf::from("/etc/chainsec/chainsec.conf")
        .is_file()
        .then(|| PathBuf::from("/etc/chainsec/chainsec.conf"))
}

fn read_config(path: &Path) -> chainsec::Result<FileConfig> {
    let bytes = fs::read(path).map_err(|source| chainsec::Error::Io {
        operation: "read configuration".to_owned(),
        path: path.to_owned(),
        source,
    })?;
    let text =
        std::str::from_utf8(&bytes).map_err(|error| chainsec::Error::InvalidConfiguration {
            message: format!("{}: {error}", path.display()),
        })?;
    toml::from_str(text).map_err(|error| chainsec::Error::InvalidConfiguration {
        message: format!("{}: {error}", path.display()),
    })
}

pub(in crate::app) fn initialize(root: &Path) -> chainsec::Result<PathBuf> {
    if let Some(path) = config_path(root) {
        return Err(chainsec::Error::InvalidConfiguration {
            message: format!("configuration already exists at {}", path.display()),
        });
    }
    let gitignore_update = prepare_gitignore_update(root)?;
    let path = root.join("chainsec.toml");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|source| chainsec::Error::Io {
            operation: "create configuration".to_owned(),
            path: path.clone(),
            source,
        })?;

    let write_result = std::io::Write::write_all(&mut file, INITIAL_CONFIG.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|source| chainsec::Error::Io {
            operation: "write configuration".to_owned(),
            path: path.clone(),
            source,
        });
    drop(file);
    if let Err(error) = write_result {
        return Err(rollback_configuration(&path, error));
    }

    if let Some((gitignore_path, updated)) = gitignore_update
        && let Err(source) = fs::write(&gitignore_path, updated)
    {
        let error = chainsec::Error::Io {
            operation: "update .gitignore".to_owned(),
            path: gitignore_path,
            source,
        };
        return Err(rollback_configuration(&path, error));
    }

    Ok(path)
}

fn prepare_gitignore_update(root: &Path) -> chainsec::Result<Option<(PathBuf, String)>> {
    let path = root.join(".gitignore");
    let existing = match fs::read_to_string(&path) {
        Ok(existing) => existing,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(source) => {
            return Err(chainsec::Error::Io {
                operation: "read .gitignore".to_owned(),
                path,
                source,
            });
        }
    };
    let has_cache = existing
        .lines()
        .any(|line| line.trim() == ".chainsec-cache");
    if has_cache {
        return Ok(None);
    }

    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(".chainsec-cache\n");
    Ok(Some((path, updated)))
}

fn rollback_configuration(path: &Path, error: chainsec::Error) -> chainsec::Error {
    match fs::remove_file(path) {
        Ok(()) => error,
        Err(source) => chainsec::Error::Io {
            operation: format!("roll back configuration after initialization failed ({error})"),
            path: path.to_owned(),
            source,
        },
    }
}

pub(in crate::app) fn load(root: &Path) -> chainsec::Result<(FileConfig, Option<PathBuf>)> {
    let repository_path = config_path(root);
    // Use exactly one global configuration source: user XDG configuration takes
    // precedence, otherwise the system configuration is the fallback.
    let global_path = global_config_path();
    let global = global_path
        .as_deref()
        .map(read_config)
        .transpose()?
        .unwrap_or_default();

    let repository = repository_path
        .as_deref()
        .map(read_config)
        .transpose()?
        .unwrap_or_default();

    // Relative rule packs resolve next to the file that supplied their value.
    let rule_packs_path = if repository.rule_packs.is_some() {
        repository_path
    } else {
        global_path
    };

    Ok((global.overlay(repository), rule_packs_path))
}

pub(in crate::app) fn configured_cache(root: &Path) -> chainsec::Result<Option<PathBuf>> {
    let (config, _) = load(root)?;
    Ok(config.cache)
}
