use std::path::Path;

use chainsec::rules;
use clap::{ArgMatches, parser::ValueSource};

use super::files::{FileConfig, SuppressionConfig, extend_hosts};
use crate::app::cli::{
    AnalysisOptions, OutputFormat, validate_analysis_threads, validate_positive_usize,
};

fn use_file_value(matches: &ArgMatches, id: &str) -> bool {
    !matches!(matches.value_source(id), Some(ValueSource::CommandLine))
}

#[derive(Debug)]
pub(in crate::app) struct AppliedConfig {
    pub(in crate::app) ignored_packages: Vec<String>,
    pub(in crate::app) suppressions: Vec<SuppressionConfig>,
}

pub(in crate::app) fn apply(
    options: &mut AnalysisOptions,
    config: FileConfig,
    config_path: Option<&Path>,
    matches: &ArgMatches,
    force_online: bool,
) -> chainsec::Result<AppliedConfig> {
    macro_rules! apply {
        ($field:ident, $arg:literal) => {
            if use_file_value(matches, $arg)
                && let Some(value) = config.$field
            {
                options.$field = value;
            }
        };
    }
    apply!(max_depth, "max_depth");
    apply!(max_packages, "max_packages");
    apply!(max_network_requests, "max_network_requests");
    apply!(max_acquisition_seconds, "max_acquisition_seconds");
    apply!(max_archive_bytes, "max_archive_bytes");
    apply!(max_extracted_bytes, "max_extracted_bytes");
    apply!(max_extracted_files, "max_extracted_files");
    apply!(max_source_file_bytes, "max_source_file_bytes");
    apply!(max_findings, "max_findings");
    apply!(max_scan_seconds, "max_scan_seconds");
    apply!(fail_on_parse_error, "fail_on_parse_error");
    validate_file_positive_usize(
        &mut options.max_network_requests,
        config.max_network_requests,
        matches,
        "max_network_requests",
    )?;
    validate_file_usize(
        &mut options.threads,
        config.threads,
        matches,
        "threads",
        validate_analysis_threads,
    )?;
    if use_file_value(matches, "cache")
        && let Some(value) = config.cache
    {
        options.cache = Some(value);
    }
    apply!(allow_unlocked, "allow_unlocked");
    apply!(trust_local_input, "trust_local_input");
    apply!(allow_insecure_http, "allow_insecure_http");
    apply!(online, "online");
    if force_online {
        options.online = true;
    }

    if let Some(hosts) = config.allowed_hosts {
        let cli_hosts = std::mem::take(&mut options.allowed_hosts);
        options.allowed_hosts = extend_hosts(Some(hosts), Some(cli_hosts)).unwrap_or_default();
    }
    if let Some(artifactories) = config.artifactories {
        let (repositories, hosts) = artifactories.apply_to(options.artifactories.clone())?;
        options.artifactories = repositories;
        if options.online {
            for host in hosts {
                if !options.allowed_hosts.contains(&host) {
                    options.allowed_hosts.push(host);
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
        options.output = Some(value);
    }
    if use_file_value(matches, "rule_packs")
        && let Some(paths) = config.rule_packs
    {
        let base = config_path.and_then(Path::parent).unwrap_or(Path::new("."));
        options.rule_packs = paths
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
        options.ignored_rules = values;
    }
    if use_file_value(matches, "ignored_paths")
        && let Some(values) = config.ignored_paths
    {
        options.ignored_paths = values;
    }

    let ignored_packages = config.ignored_packages.unwrap_or_default();
    validate_ignored_packages(&ignored_packages)?;
    let suppressions = config.suppressions.unwrap_or_default();
    validate_suppressions(&suppressions)?;
    if options.verbose && !matches!(options.format, OutputFormat::Human) {
        return Err(chainsec::Error::InvalidConfiguration {
            message: "--verbose is only valid with --format human".to_owned(),
        });
    }
    Ok(AppliedConfig {
        ignored_packages,
        suppressions,
    })
}

fn validate_file_positive_usize(
    option: &mut usize,
    value: Option<usize>,
    matches: &ArgMatches,
    name: &str,
) -> chainsec::Result<()> {
    validate_file_usize(option, value, matches, name, validate_positive_usize)
}

fn validate_file_usize(
    option: &mut usize,
    value: Option<usize>,
    matches: &ArgMatches,
    name: &str,
    validate: impl FnOnce(usize) -> Result<usize, String>,
) -> chainsec::Result<()> {
    if use_file_value(matches, name)
        && let Some(value) = value
    {
        validate(value).map_err(|message| chainsec::Error::InvalidConfiguration {
            message: format!("{name} {message}"),
        })?;
        *option = value;
    }
    Ok(())
}

fn validate_suppressions(suppressions: &[SuppressionConfig]) -> chainsec::Result<()> {
    for suppression in suppressions {
        rules::parse_rule_selector(&suppression.rule)?;
        if suppression.reason.trim().is_empty() {
            return Err(chainsec::Error::InvalidConfiguration {
                message: format!(
                    "suppression for rule {:?} must include a reason",
                    suppression.rule
                ),
            });
        }
        if let Some(package) = &suppression.package
            && package.trim().is_empty()
        {
            return Err(chainsec::Error::InvalidConfiguration {
                message: format!(
                    "suppression for rule {:?} has an empty package",
                    suppression.rule
                ),
            });
        }
    }
    Ok(())
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

pub(in crate::app) fn parse_human_size(value: &str) -> Result<u64, String> {
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
