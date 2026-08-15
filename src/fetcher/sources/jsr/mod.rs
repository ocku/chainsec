mod package;
mod resolution;
mod selection;

#[cfg(test)]
use std::{fs, path::Path};

#[cfg(test)]
use serde_json::Value as JsonValue;
#[cfg(test)]
use sha2::{Digest, Sha256};

#[cfg(test)]
use crate::{
    error::Error,
    fetcher::{RemoteVersionSelection, SourceFetcher, filesystem::TrustedDir},
    model::{Dependency, EngineLimits},
};
#[cfg(test)]
use url::Url;

#[cfg(test)]
use package::read_cached_jsr_file;
#[cfg(test)]
use selection::{
    jsr_compare_versions, jsr_package_and_requirement, jsr_range_versions,
    jsr_versions_at_or_below, select_jsr_version,
};

#[cfg(test)]
mod tests;
