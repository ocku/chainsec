use std::{path::Path, process::ExitCode};

use crate::app::{
    canonicalize_root,
    cli::{CacheCommand, CacheSubcommand},
    config, configuration_error, default_cache_path, purge_cache,
};

pub(super) fn execute(cache_command: CacheCommand) -> ExitCode {
    match cache_command.command {
        CacheSubcommand::Purge(purge) => {
            let path = match purge.cache {
                Some(path) => path,
                None => match canonicalize_root(Path::new("."))
                    .and_then(|root| config::configured_cache(&root))
                {
                    Ok(Some(path)) => path,
                    Ok(None) => default_cache_path(),
                    Err(error) => return configuration_error(error),
                },
            };
            match purge_cache(&path) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => configuration_error(error),
            }
        }
    }
}
