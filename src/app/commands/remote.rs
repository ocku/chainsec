use std::{path::PathBuf, process::ExitCode};

use chainsec::RemoteVersionSelection;
use clap::ArgMatches;

use crate::app::{
    analysis::ScanTarget,
    cli::{RemoteCommand, RemoteSubcommand},
    execute_scan,
};

pub(super) async fn execute(remote: RemoteCommand, matches: &ArgMatches) -> ExitCode {
    let remote_matches = matches
        .subcommand_matches("remote")
        .expect("remote command matched");
    match remote.command {
        RemoteSubcommand::Scan(mut scan) => {
            let command_matches = remote_matches
                .subcommand_matches("scan")
                .expect("remote scan command matched");
            let config_root = PathBuf::from(".");
            let selection = scan.diff.map(RemoteVersionSelection::Last);
            execute_scan(
                &mut scan.options,
                ScanTarget::Remote(&scan.package),
                &config_root,
                command_matches,
                selection,
            )
            .await
        }
        RemoteSubcommand::Diff(mut diff) => {
            let command_matches = remote_matches
                .subcommand_matches("diff")
                .expect("remote diff command matched");
            let config_root = PathBuf::from(".");
            let selection = diff.selection();
            execute_scan(
                &mut diff.options,
                ScanTarget::Remote(&diff.package),
                &config_root,
                command_matches,
                Some(selection),
            )
            .await
        }
    }
}
