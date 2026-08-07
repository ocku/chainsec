use std::{io, path::PathBuf};

use snafu::Snafu;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum Error {
    #[snafu(display("{operation} {}: {source}", path.display()))]
    Io {
        operation: String,
        path: PathBuf,
        source: io::Error,
    },

    #[snafu(display("manifest error in {}: {message}", path.display()))]
    Manifest { path: PathBuf, message: String },

    #[snafu(display("could not resolve {package}: {message}"))]
    Resolution { package: String, message: String },

    #[snafu(display("could not fetch {package} from {source_url}: {message}"))]
    Fetch {
        package: String,
        source_url: String,
        message: String,
    },

    #[snafu(display("could not extract {}: {message}", archive.display()))]
    Extraction { archive: PathBuf, message: String },

    #[snafu(display("could not scan {}: {message}", path.display()))]
    Scan { path: PathBuf, message: String },

    #[snafu(display("policy denied {operation}: {message}"))]
    Policy { operation: String, message: String },

    #[snafu(display("{resource} limit exceeded (limit: {limit})"))]
    LimitExceeded { resource: String, limit: u64 },

    #[snafu(display("invalid configuration: {message}"))]
    InvalidConfiguration { message: String },
}

impl Error {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Io { .. } => "io_error",
            Self::Manifest { .. } => "manifest_error",
            Self::Resolution { .. } => "resolution_error",
            Self::Fetch { .. } => "fetch_error",
            Self::Extraction { .. } => "extraction_error",
            Self::Scan { .. } => "scan_error",
            Self::Policy { .. } => "policy_error",
            Self::LimitExceeded { .. } => "limit_exceeded",
            Self::InvalidConfiguration { .. } => "invalid_configuration",
        }
    }

    #[must_use]
    pub const fn is_policy(&self) -> bool {
        matches!(self, Self::Policy { .. } | Self::LimitExceeded { .. })
    }
}
