mod analysis;
pub(crate) mod cli;
mod commands;
mod config;
mod core;
mod diff;
mod output;
mod remote;
mod style;

use std::{
    env, fs,
    io::{self, IsTerminal},
    path::{Path, PathBuf},
    process::ExitCode,
};

use chainsec::{RemoteVersionSelection, model::Risk};
use clap::{CommandFactory, FromArgMatches};
use tracing::error;
use tracing_subscriber::EnvFilter;

use self::{
    analysis::ScanTarget,
    cli::{AnalysisOptions, Cli, OutputFormat},
    config::AppliedConfig,
    output::exit_status,
};

pub(super) async fn execute() -> ExitCode {
    let matches = Cli::command().get_matches();
    let cli = Cli::from_arg_matches(&matches).expect("clap parsed its own arguments");

    commands::execute(cli, &matches).await
}

pub(in crate::app) async fn execute_scan(
    options: &mut AnalysisOptions,
    target: ScanTarget<'_>,
    config_root: &Path,
    matches: &clap::ArgMatches,
    diff_selection: Option<RemoteVersionSelection>,
) -> ExitCode {
    let applied = match prepare_scan(options, target, config_root, matches) {
        Ok(applied) => applied,
        Err(error) => return configuration_error(error),
    };

    let outcome = if let Some(selection) = diff_selection {
        execute_diff_analysis(options, target, selection, &applied).await
    } else {
        execute_single_analysis(options, target, &applied).await
    };

    match outcome {
        Ok(rendered) => emit_rendered(rendered, options.output.as_deref()),
        Err(error) => analysis_error(error),
    }
}

struct RenderedAnalysis {
    output: String,
    exit_status: u8,
}

/// Resolves configuration and prepares a scan without choosing the analysis
/// mode. Keeps all the fallible setup in one place so the two analysis paths
/// below only deal with their own concerns.
fn prepare_scan(
    options: &mut AnalysisOptions,
    target: ScanTarget<'_>,
    config_root: &Path,
    matches: &clap::ArgMatches,
) -> chainsec::Result<AppliedConfig> {
    let root =
        canonicalize_root(config_root).map_err(|error| chainsec::Error::InvalidConfiguration {
            message: error.to_string(),
        })?;
    let (config, config_path) = config::load(&root)?;
    let remote = matches!(target, ScanTarget::Remote(_));
    let applied = config::apply(options, config, config_path.as_deref(), matches, remote)?;
    options.cache = Some(options.cache.take().unwrap_or_else(default_cache_path));
    if let ScanTarget::Remote(package) = target
        && let Err(error) = remote::add_allowed_host(options, package)
    {
        return Err(error);
    }

    configure_tracing(
        io::stdout().is_terminal()
            && options.output.is_none()
            && !matches!(options.format, OutputFormat::Human),
    );
    Ok(applied)
}

async fn execute_single_analysis(
    options: &AnalysisOptions,
    target: ScanTarget<'_>,
    applied: &AppliedConfig,
) -> chainsec::Result<RenderedAnalysis> {
    let (threshold, color) = presentation(options);
    let (report, output) = analysis::run(
        options,
        target,
        &applied.ignored_packages,
        &options.ignored_paths,
        &applied.suppressions,
        color,
    )
    .await?;

    Ok(RenderedAnalysis {
        exit_status: exit_status(&report, threshold),
        output,
    })
}

async fn execute_diff_analysis(
    options: &AnalysisOptions,
    target: ScanTarget<'_>,
    selection: RemoteVersionSelection,
    applied: &AppliedConfig,
) -> chainsec::Result<RenderedAnalysis> {
    let ScanTarget::Remote(package) = target else {
        return Err(chainsec::Error::InvalidConfiguration {
            message: "remote version diffs are available only for remote packages".to_owned(),
        });
    };
    let (threshold, color) = presentation(options);
    let (reports, output) = analysis::run_diff(
        options,
        package,
        selection,
        &applied.ignored_packages,
        &options.ignored_paths,
        &applied.suppressions,
        color,
    )
    .await?;

    Ok(RenderedAnalysis {
        exit_status: diff::exit_status(&reports, threshold),
        output,
    })
}

fn presentation(options: &AnalysisOptions) -> (Risk, bool) {
    let stdout_is_terminal = io::stdout().is_terminal();
    let threshold = Risk::from(options.fail_on);
    let color = matches!(options.format, OutputFormat::Human)
        && options.output.is_none()
        && stdout_is_terminal;
    (threshold, color)
}

fn emit_rendered(rendered: RenderedAnalysis, output_path: Option<&Path>) -> ExitCode {
    match write_report(output_path, &rendered.output) {
        Ok(()) => ExitCode::from(rendered.exit_status),
        Err(error) => {
            report_write_error(output_path, &error);
            ExitCode::from(3)
        }
    }
}

fn report_write_error(path: Option<&Path>, error: &io::Error) {
    if let Some(path) = path {
        error!(path = %path.display(), error = %error, "could not write analysis report");
        eprintln!("chainsec: could not write {}: {error}", path.display());
    } else {
        eprintln!("chainsec: could not write report: {error}");
    }
}

fn analysis_error(error: chainsec::Error) -> ExitCode {
    tracing::error!(error = %error, "analysis failed");
    eprintln!("chainsec: {error}");
    ExitCode::from(pre_report_exit_status(&error))
}

fn pre_report_exit_status(error: &chainsec::Error) -> u8 {
    match error {
        chainsec::Error::InvalidConfiguration { .. } => 2,
        chainsec::Error::Io { .. }
        | chainsec::Error::Manifest { .. }
        | chainsec::Error::Resolution { .. }
        | chainsec::Error::Fetch { .. }
        | chainsec::Error::Extraction { .. }
        | chainsec::Error::Scan { .. } => 3,
        chainsec::Error::Policy { .. } | chainsec::Error::LimitExceeded { .. } => 4,
    }
}

pub(super) fn canonicalize_root(path: &Path) -> chainsec::Result<PathBuf> {
    fs::canonicalize(path).map_err(|source| chainsec::Error::Io {
        operation: "resolve project directory".to_owned(),
        path: path.to_owned(),
        source,
    })
}

pub(super) fn default_cache_path() -> PathBuf {
    if env::current_dir()
        .ok()
        .is_some_and(|directory| directory.join("chainsec.toml").is_file())
    {
        return PathBuf::from(".chainsec-cache");
    }

    if let Some(directory) = env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(directory).join("chainsec");
    }
    if let Some(home) = env::var_os("HOME") {
        return PathBuf::from(home).join(".cache/chainsec");
    }
    env::temp_dir().join("chainsec")
}

pub(super) fn purge_cache(path: &Path) -> chainsec::Result<()> {
    if chainsec::purge_cache(path)? {
        println!("purged cache at {}", path.display());
    } else {
        println!("cache does not exist at {}", path.display());
    }
    Ok(())
}

pub(super) fn configuration_error(error: chainsec::Error) -> ExitCode {
    eprintln!("chainsec: {error}");
    ExitCode::from(pre_report_exit_status(&error))
}

fn write_report(output_path: Option<&Path>, rendered: &str) -> io::Result<()> {
    if let Some(path) = output_path {
        std::fs::write(path, rendered)
    } else {
        println!("{rendered}");
        Ok(())
    }
}

fn configure_tracing(to_stderr: bool) {
    if !io::stdout().is_terminal() {
        return;
    }

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let writer = tracing_subscriber::fmt::writer::BoxMakeWriter::new(
        move || -> Box<dyn io::Write + Send> {
            if to_stderr {
                Box::new(io::stderr())
            } else {
                Box::new(io::stdout())
            }
        },
    );
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .with_ansi(true)
        .without_time()
        .with_target(false)
        .init();
}

#[cfg(test)]
mod tests {
    use std::{io, path::PathBuf};

    use super::pre_report_exit_status;

    #[test]
    fn pre_report_errors_use_documented_exit_statuses() {
        let path = PathBuf::from("fixture");
        let operational_errors = [
            chainsec::Error::Io {
                operation: "read".to_owned(),
                path: path.clone(),
                source: io::Error::other("failed"),
            },
            chainsec::Error::Manifest {
                path: path.clone(),
                message: "failed".to_owned(),
            },
            chainsec::Error::Resolution {
                package: "example".to_owned(),
                message: "failed".to_owned(),
            },
            chainsec::Error::Fetch {
                package: "example".to_owned(),
                source_url: "https://example.test/package".to_owned(),
                message: "failed".to_owned(),
            },
            chainsec::Error::Extraction {
                archive: path.clone(),
                message: "failed".to_owned(),
            },
            chainsec::Error::Scan {
                path,
                message: "failed".to_owned(),
            },
        ];
        for error in &operational_errors {
            assert_eq!(pre_report_exit_status(error), 3, "{}", error.code());
        }

        let invalid = chainsec::Error::InvalidConfiguration {
            message: "invalid".to_owned(),
        };
        assert_eq!(pre_report_exit_status(&invalid), 2);

        let policy_errors = [
            chainsec::Error::Policy {
                operation: "fetch".to_owned(),
                message: "denied".to_owned(),
            },
            chainsec::Error::LimitExceeded {
                resource: "packages".to_owned(),
                limit: 1,
            },
        ];
        for error in &policy_errors {
            assert_eq!(pre_report_exit_status(error), 4, "{}", error.code());
        }
    }
}
