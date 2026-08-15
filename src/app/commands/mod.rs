mod cache;
mod init;
mod remote;
mod scan;

use std::process::ExitCode;

use clap::ArgMatches;

use crate::app::cli::{Cli, Command};

pub(super) async fn execute(cli: Cli, matches: &ArgMatches) -> ExitCode {
    match cli.command {
        Command::Scan(scan) => scan::execute(scan, matches).await,
        Command::Remote(remote) => remote::execute(remote, matches).await,
        Command::Init(init) => init::execute(init),
        Command::Cache(cache) => cache::execute(cache),
    }
}
