mod analysis;
pub(crate) mod cli;
mod config;
mod output;
mod remote;

use std::{
    env, fs,
    io::{self, IsTerminal},
    path::{Path, PathBuf},
    process::ExitCode,
};

use chainsec::model::Risk;
use clap::{CommandFactory, FromArgMatches};
use tracing::error;
use tracing_subscriber::EnvFilter;

use self::{
    cli::{Cli, OutputFormat},
    output::exit_status,
};

pub(super) async fn execute() -> ExitCode {
    let matches = Cli::command().get_matches();
    let mut cli = Cli::from_arg_matches(&matches).expect("clap parsed its own arguments");
    let root = fs::canonicalize(&cli.path).map_err(|source| chainsec::Error::Io {
        operation: "resolve project directory".to_owned(),
        path: cli.path.clone(),
        source,
    });
    let root = match root {
        Ok(root) => root,
        Err(error) => return configuration_error(error),
    };
    if cli.init {
        return match config::initialize(&root) {
            Ok(path) => {
                println!("created {}", path.display());
                ExitCode::SUCCESS
            }
            Err(error) => configuration_error(error),
        };
    }
    let (config, config_path) = match config::load(&root) {
        Ok(value) => value,
        Err(error) => return configuration_error(error),
    };

    let (ignored_packages, ignored_paths, suppressions) =
        match config::apply(&mut cli, config, config_path.as_deref(), &matches) {
            Ok(value) => value,
            Err(error) => return configuration_error(error),
        };
    cli.cache = Some(cli.cache.take().unwrap_or_else(default_cache_path));
    if cli.cache_purge {
        return match purge_cache(cli.cache.as_deref().expect("cache path was resolved")) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => configuration_error(error),
        };
    }
    if let Err(error) = remote::add_allowed_host(&mut cli) {
        return configuration_error(error);
    }

    let stdout_is_terminal = io::stdout().is_terminal();
    configure_tracing();
    let threshold = Risk::from(cli.fail_on);
    let color =
        matches!(cli.format, OutputFormat::Human) && cli.output.is_none() && stdout_is_terminal;

    match analysis::run(
        &cli,
        &ignored_packages,
        &ignored_paths,
        &suppressions,
        color,
    )
    .await
    {
        Ok((report, rendered)) => {
            if let Err(error) = write_report(cli.output.as_deref(), &rendered) {
                if let Some(path) = &cli.output {
                    error!(path = %path.display(), error = %error, "could not write analysis report");
                    eprintln!("chainsec: could not write {}: {error}", path.display());
                } else {
                    eprintln!("chainsec: could not write report: {error}");
                }
                return ExitCode::from(3);
            }

            ExitCode::from(exit_status(&report, threshold))
        }
        Err(error) => {
            error!(error = %error, "analysis failed");
            eprintln!("chainsec: {error}");
            ExitCode::from(if error.is_policy() { 4 } else { 2 })
        }
    }
}

fn default_cache_path() -> PathBuf {
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

fn purge_cache(path: &Path) -> chainsec::Result<()> {
    if !path.exists() {
        println!("cache does not exist at {}", path.display());
        return Ok(());
    }
    fs::remove_dir_all(path).map_err(|source| chainsec::Error::Io {
        operation: "purge cache directory".to_owned(),
        path: path.to_owned(),
        source,
    })?;
    println!("purged cache at {}", path.display());
    Ok(())
}

fn configuration_error(error: chainsec::Error) -> ExitCode {
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

fn configure_tracing() {
    if !io::stdout().is_terminal() {
        return;
    }

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stdout)
        .with_ansi(true)
        .without_time()
        .with_target(false)
        .init();
}
