#[cfg(not(unix))]
compile_error!("ChainSec only supports Unix targets (Linux, macOS, and other Unix-like systems).");

pub mod engine;
pub mod error;
pub mod fetcher;
pub mod manifests;
pub mod model;
pub mod rules;
pub mod scanner;

pub use engine::Engine;
pub use error::{Error, Result};
pub use fetcher::{
    ArtifactRepositories, FetchPolicy, Fetcher, RemoteVersionSelection, SourceFetcher, purge_cache,
};
pub use model::{EngineLimits, Report, parse_remote_package};
