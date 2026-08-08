use std::{
    env, fs,
    path::{Path, PathBuf},
};

use clap::{ArgMatches, parser::ValueSource};
use serde::Deserialize;
use url::Url;

use super::cli::{Cli, OutputFormat, Severity};
use chainsec::ArtifactRepositories;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArtifactoriesConfig {
    npm: Option<ArtifactoryConfig>,
    pypi: Option<ArtifactoryConfig>,
    jsr: Option<ArtifactoryConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactoryConfig {
    metadata_base_url: String,
    credential: Option<CredentialConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialConfig {
    scope: String,
    bearer_token_env: String,
}

impl CredentialConfig {
    fn apply_to(
        self,
        repositories: ArtifactRepositories,
    ) -> chainsec::Result<ArtifactRepositories> {
        let token = env::var(&self.bearer_token_env).map_err(|error| {
            chainsec::Error::InvalidConfiguration {
                message: format!(
                    "credential environment variable {:?} is unavailable: {error}",
                    self.bearer_token_env
                ),
            }
        })?;
        repositories.with_bearer_token(self.scope, token)
    }
}

impl ArtifactoriesConfig {
    fn overlay(self, overriding: Self) -> Self {
        Self {
            npm: overriding.npm.or(self.npm),
            pypi: overriding.pypi.or(self.pypi),
            jsr: overriding.jsr.or(self.jsr),
        }
    }

    fn apply_to(
        self,
        repositories: ArtifactRepositories,
    ) -> chainsec::Result<(ArtifactRepositories, Vec<String>)> {
        let (repositories, npm_host) =
            apply_artifactory(repositories, self.npm, |repositories, url| {
                repositories.with_npm_metadata_base_url(url)
            })?;
        let (repositories, pypi_host) =
            apply_artifactory(repositories, self.pypi, |repositories, url| {
                repositories.with_pypi_metadata_base_url(url)
            })?;
        let (repositories, jsr_host) =
            apply_artifactory(repositories, self.jsr, |repositories, url| {
                repositories.with_jsr_metadata_base_url(url)
            })?;
        Ok((
            repositories,
            [npm_host, pypi_host, jsr_host]
                .into_iter()
                .flatten()
                .collect(),
        ))
    }
}

fn apply_artifactory(
    repositories: ArtifactRepositories,
    artifactory: Option<ArtifactoryConfig>,
    set_metadata_url: impl FnOnce(
        ArtifactRepositories,
        String,
    ) -> chainsec::Result<ArtifactRepositories>,
) -> chainsec::Result<(ArtifactRepositories, Option<String>)> {
    let Some(artifactory) = artifactory else {
        return Ok((repositories, None));
    };

    let metadata_base_url = artifactory.metadata_base_url;
    let repositories = set_metadata_url(repositories, metadata_base_url.clone())?;
    let host = Url::parse(&metadata_base_url)
        .expect("validated Artifactory metadata URL")
        .host_str()
        .expect("validated Artifactory metadata URL has a host")
        .to_owned();
    let repositories = match artifactory.credential {
        Some(credential) => credential.apply_to(repositories)?,
        None => repositories,
    };
    Ok((repositories, Some(host)))
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileConfig {
    max_depth: Option<usize>,
    max_packages: Option<usize>,
    max_archive_bytes: Option<u64>,
    max_extracted_bytes: Option<u64>,
    max_extracted_files: Option<u64>,
    max_source_file_bytes: Option<u64>,
    max_scan_seconds: Option<u64>,
    cache: Option<PathBuf>,
    allow_unlocked: Option<bool>,
    trust_local_input: Option<bool>,
    online: Option<bool>,
    allowed_hosts: Option<Vec<String>>,
    artifactories: Option<ArtifactoriesConfig>,
    rule_packs: Option<Vec<PathBuf>>,
    no_default_rules: Option<bool>,
    ignored_rules: Option<Vec<String>>,
    ignored_packages: Option<Vec<String>>,
    ignored_paths: Option<Vec<String>>,
    format: Option<OutputFormat>,
    fail_on: Option<Severity>,
    output: Option<PathBuf>,
}

impl FileConfig {
    /// Overlay repository settings on global settings. `Some` values in
    /// `overriding` replace the corresponding global value.
    fn overlay(self, overriding: Self) -> Self {
        Self {
            max_depth: overriding.max_depth.or(self.max_depth),
            max_packages: overriding.max_packages.or(self.max_packages),
            max_archive_bytes: overriding.max_archive_bytes.or(self.max_archive_bytes),
            max_extracted_bytes: overriding.max_extracted_bytes.or(self.max_extracted_bytes),
            max_extracted_files: overriding.max_extracted_files.or(self.max_extracted_files),
            max_source_file_bytes: overriding
                .max_source_file_bytes
                .or(self.max_source_file_bytes),
            max_scan_seconds: overriding.max_scan_seconds.or(self.max_scan_seconds),
            cache: overriding.cache.or(self.cache),
            allow_unlocked: overriding.allow_unlocked.or(self.allow_unlocked),
            trust_local_input: overriding.trust_local_input.or(self.trust_local_input),
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
            ignored_packages: overriding.ignored_packages.or(self.ignored_packages),
            ignored_paths: overriding.ignored_paths.or(self.ignored_paths),
            format: overriding.format.or(self.format),
            fail_on: overriding.fail_on.or(self.fail_on),
            output: overriding.output.or(self.output),
        }
    }
}

fn extend_hosts(base: Option<Vec<String>>, extending: Option<Vec<String>>) -> Option<Vec<String>> {
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
max_depth = 3
max_packages = 500

# Network access remains disabled unless both options below are configured.
# online = true
# allowed_hosts = ["registry.npmjs.org", "pypi.org", "files.pythonhosted.org"]

# Optional repository-manager endpoints. These replace only metadata lookup;
# locked artifact URLs are still honored and integrity-checked. Credentials are
# read only from explicitly named environment variables.
# [artifactories.npm]
# metadata_base_url = "https://packages.example/npm"
#
# [artifactories.npm.credential]
# scope = "https://packages.example/"
# bearer_token_env = "PACKAGE_REGISTRY_TOKEN"
#
# [artifactories.pypi]
# metadata_base_url = "https://packages.example/pypi"

# Ignore generated or test-only root-project paths. Dependencies are unaffected.
ignored_paths = ["tests/**"]

# Examples:
# ignored_rules = ["network:*"]
# ignored_packages = ["npm:legacy-package@1.2.3"]
# fail_on = "high"
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

pub(super) fn initialize(root: &Path) -> chainsec::Result<PathBuf> {
    if let Some(path) = config_path(root) {
        return Err(chainsec::Error::InvalidConfiguration {
            message: format!("configuration already exists at {}", path.display()),
        });
    }
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
    std::io::Write::write_all(&mut file, INITIAL_CONFIG.as_bytes()).map_err(|source| {
        chainsec::Error::Io {
            operation: "write configuration".to_owned(),
            path: path.clone(),
            source,
        }
    })?;
    append_cache_to_gitignore(root)?;
    Ok(path)
}

fn append_cache_to_gitignore(root: &Path) -> chainsec::Result<()> {
    let path = root.join(".gitignore");
    let existing = fs::read_to_string(&path).unwrap_or_default();
    if existing
        .lines()
        .any(|line| line.trim() == ".chainsec-cache")
    {
        return Ok(());
    }

    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(".chainsec-cache\n");
    fs::write(&path, updated).map_err(|source| chainsec::Error::Io {
        operation: "update .gitignore".to_owned(),
        path,
        source,
    })
}

pub(super) fn load(root: &Path) -> chainsec::Result<(FileConfig, Option<PathBuf>)> {
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

fn use_file_value(matches: &ArgMatches, id: &str) -> bool {
    !matches!(matches.value_source(id), Some(ValueSource::CommandLine))
}

pub(super) fn apply(
    cli: &mut Cli,
    config: FileConfig,
    config_path: Option<&Path>,
    matches: &ArgMatches,
) -> chainsec::Result<(Vec<String>, Vec<String>)> {
    macro_rules! apply {
        ($field:ident, $arg:literal) => {
            if use_file_value(matches, $arg)
                && let Some(value) = config.$field
            {
                cli.$field = value;
            }
        };
    }
    apply!(max_depth, "max_depth");
    apply!(max_packages, "max_packages");
    apply!(max_archive_bytes, "max_archive_bytes");
    apply!(max_extracted_bytes, "max_extracted_bytes");
    apply!(max_extracted_files, "max_extracted_files");
    apply!(max_source_file_bytes, "max_source_file_bytes");
    apply!(max_scan_seconds, "max_scan_seconds");
    if use_file_value(matches, "cache")
        && let Some(value) = config.cache
    {
        cli.cache = Some(value);
    }
    apply!(allow_unlocked, "allow_unlocked");
    apply!(trust_local_input, "trust_local_input");
    apply!(online, "online");
    // A remote traversal root necessarily requires network acquisition; it takes
    // precedence over a configuration file's offline default.
    if cli.remote.is_some() {
        cli.online = true;
    }
    if let Some(hosts) = config.allowed_hosts {
        let cli_hosts = std::mem::take(&mut cli.allowed_hosts);
        cli.allowed_hosts = extend_hosts(Some(hosts), Some(cli_hosts)).unwrap_or_default();
    }
    if let Some(artifactories) = config.artifactories {
        let (repositories, hosts) = artifactories.apply_to(cli.artifactories.clone())?;
        cli.artifactories = repositories;
        if cli.online {
            for host in hosts {
                if !cli.allowed_hosts.contains(&host) {
                    cli.allowed_hosts.push(host);
                }
            }
        }
    }
    apply!(no_default_rules, "no_default_rules");
    apply!(format, "format");
    apply!(fail_on, "fail_on");

    if use_file_value(matches, "output")
        && let Some(value) = config.output
    {
        cli.output = Some(value);
    }
    if use_file_value(matches, "rule_packs")
        && let Some(paths) = config.rule_packs
    {
        let base = config_path.and_then(Path::parent).unwrap_or(Path::new("."));
        cli.rule_packs = paths
            .into_iter()
            .map(|path| {
                if path.is_absolute() {
                    path
                } else {
                    base.join(path)
                }
            })
            .collect();
    }
    if use_file_value(matches, "ignored_rules")
        && let Some(values) = config.ignored_rules
    {
        cli.ignored_rules = values;
    }

    let ignored_packages = config.ignored_packages.unwrap_or_default();
    validate_ignored_packages(&ignored_packages)?;
    Ok((ignored_packages, config.ignored_paths.unwrap_or_default()))
}

fn validate_ignored_packages(packages: &[String]) -> chainsec::Result<()> {
    for package in packages {
        let valid = package.split_once(':').is_some_and(|(source, remainder)| {
            remainder.rsplit_once('@').is_some_and(|(name, version)| {
                matches!(source, "python" | "npm" | "deno")
                    && !name.is_empty()
                    && !version.is_empty()
            })
        });
        if !valid {
            return Err(chainsec::Error::InvalidConfiguration {
                message: format!(
                    "invalid ignored package {package:?}; expected source:name@version"
                ),
            });
        }
    }
    Ok(())
}

pub(super) fn parse_human_size(value: &str) -> Result<u64, String> {
    let value = value.trim();
    let split_at = value
        .find(|character: char| !character.is_ascii_digit() && character != '.')
        .unwrap_or(value.len());
    let (number, suffix) = value.split_at(split_at);
    if number.is_empty() || number == "." || number.matches('.').count() > 1 {
        return Err(format!("invalid size {value:?}"));
    }

    let multiplier = match suffix.to_ascii_lowercase().as_str() {
        "" | "b" => 1_u64,
        "k" | "kb" | "kib" => 1024,
        "m" | "mb" | "mib" => 1024 * 1024,
        "g" | "gb" | "gib" => 1024 * 1024 * 1024,
        "t" | "tb" | "tib" => 1024 * 1024 * 1024 * 1024,
        _ => return Err(format!("invalid size suffix in {value:?}")),
    };
    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    let whole = whole
        .parse::<u64>()
        .map_err(|_| format!("invalid size {value:?}"))?;
    let fraction_value = if fraction.is_empty() {
        0
    } else {
        fraction
            .parse::<u64>()
            .map_err(|_| format!("invalid size {value:?}"))?
    };
    let precision =
        u32::try_from(fraction.len()).map_err(|_| format!("size is too precise: {value:?}"))?;
    let scale = 10_u64
        .checked_pow(precision)
        .ok_or_else(|| format!("size is too precise: {value:?}"))?;
    let bytes = (u128::from(whole) * u128::from(scale) + u128::from(fraction_value))
        .checked_mul(u128::from(multiplier))
        .ok_or_else(|| format!("size is too large: {value:?}"))?
        / u128::from(scale);
    u64::try_from(bytes).map_err(|_| format!("size is too large: {value:?}"))
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, FromArgMatches};

    use super::{Cli, FileConfig, apply};

    #[test]
    fn remote_forces_online_when_configuration_disables_it() {
        let matches = Cli::command()
            .try_get_matches_from(["chainsec", "--remote", "npm:express"])
            .unwrap();
        let mut cli = Cli::from_arg_matches(&matches).unwrap();
        let config: FileConfig = toml::from_str("online = false").unwrap();

        apply(&mut cli, config, None, &matches).unwrap();

        assert!(cli.online);
    }
}
