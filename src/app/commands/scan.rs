use std::process::ExitCode;

use clap::ArgMatches;

use crate::app::{analysis::ScanTarget, cli::LocalScan, execute_scan};

pub(super) async fn execute(mut scan: LocalScan, matches: &ArgMatches) -> ExitCode {
    let command_matches = matches
        .subcommand_matches("scan")
        .expect("scan command matched");
    execute_scan(
        &mut scan.options,
        ScanTarget::Local(&scan.path),
        &scan.path,
        command_matches,
        None,
    )
    .await
}
