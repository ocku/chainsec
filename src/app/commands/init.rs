use std::process::ExitCode;

use crate::app::{canonicalize_root, cli::Init, config, configuration_error};

pub(super) fn execute(init: Init) -> ExitCode {
    match canonicalize_root(&init.path) {
        Ok(root) => match config::initialize(&root) {
            Ok(path) => {
                println!("created {}", path.display());
                ExitCode::SUCCESS
            }
            Err(error) => configuration_error(error),
        },
        Err(error) => configuration_error(error),
    }
}
