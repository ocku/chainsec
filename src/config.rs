use std::{
    fs,
    path::{Path, PathBuf},
};

use clap::{ArgMatches, parser::ValueSource};
use serde::Deserialize;

use crate::{Cli, OutputFormat, Severity};

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
    rule_packs: Option<Vec<PathBuf>>,
    no_default_rules: Option<bool>,
    ignored_rules: Option<Vec<String>>,
    ignored_packages: Option<Vec<String>>,
    ignored_paths: Option<Vec<String>>,
    format: Option<OutputFormat>,
    fail_on: Option<Severity>,
    output: Option<PathBuf>,
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
    Ok(path)
}

pub(super) fn load(root: &Path) -> chainsec::Result<(FileConfig, Option<PathBuf>)> {
    let Some(path) = config_path(root) else {
        return Ok((FileConfig::default(), None));
    };
    let bytes = fs::read(&path).map_err(|source| chainsec::Error::Io {
        operation: "read configuration".to_owned(),
        path: path.clone(),
        source,
    })?;
    let text =
        std::str::from_utf8(&bytes).map_err(|error| chainsec::Error::InvalidConfiguration {
            message: format!("{}: {error}", path.display()),
        })?;
    let config = toml::from_str(text).map_err(|error| chainsec::Error::InvalidConfiguration {
        message: format!("{}: {error}", path.display()),
    })?;
    Ok((config, Some(path)))
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
    apply!(cache, "cache");
    apply!(allow_unlocked, "allow_unlocked");
    apply!(trust_local_input, "trust_local_input");
    apply!(online, "online");
    apply!(allowed_hosts, "allowed_hosts");
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
