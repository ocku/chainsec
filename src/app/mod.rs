mod analysis;
pub(crate) mod cli;
mod commands;
mod config;
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
    let root = match canonicalize_root(config_root) {
        Ok(root) => root,
        Err(error) => return configuration_error(error),
    };
    let (config, config_path) = match config::load(&root) {
        Ok(value) => value,
        Err(error) => return configuration_error(error),
    };
    let remote = matches!(target, ScanTarget::Remote(_));
    let applied = match config::apply(options, config, config_path.as_deref(), matches, remote) {
        Ok(value) => value,
        Err(error) => return configuration_error(error),
    };
    options.cache = Some(options.cache.take().unwrap_or_else(default_cache_path));
    if let ScanTarget::Remote(package) = target
        && let Err(error) = remote::add_allowed_host(options, package)
    {
        return configuration_error(error);
    }

    let stdout_is_terminal = io::stdout().is_terminal();
    configure_tracing(
        stdout_is_terminal
            && options.output.is_none()
            && !matches!(options.format, OutputFormat::Human),
    );
    let threshold = Risk::from(options.fail_on);
    let color = matches!(options.format, OutputFormat::Human)
        && options.output.is_none()
        && stdout_is_terminal;

    if let Some(selection) = diff_selection {
        let ScanTarget::Remote(package) = target else {
            return configuration_error(chainsec::Error::InvalidConfiguration {
                message: "remote version diffs are available only for remote packages".to_owned(),
            });
        };
        return match analysis::run_diff(
            options,
            package,
            selection,
            &applied.ignored_packages,
            &options.ignored_paths,
            &applied.suppressions,
            color,
        )
        .await
        {
            Ok((reports, rendered)) => {
                if let Err(error) = write_report(options.output.as_deref(), &rendered) {
                    report_write_error(options.output.as_deref(), &error);
                    return ExitCode::from(3);
                }
                ExitCode::from(diff::exit_status(&reports, threshold))
            }
            Err(error) => analysis_error(error),
        };
    }

    match analysis::run(
        options,
        target,
        &applied.ignored_packages,
        &options.ignored_paths,
        &applied.suppressions,
        color,
    )
    .await
    {
        Ok((report, rendered)) => {
            if let Err(error) = write_report(options.output.as_deref(), &rendered) {
                report_write_error(options.output.as_deref(), &error);
                return ExitCode::from(3);
            }

            ExitCode::from(exit_status(&report, threshold))
        }
        Err(error) => analysis_error(error),
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
    ExitCode::from(if error.is_policy() { 4 } else { 2 })
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
    ExitCode::from(2)
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
