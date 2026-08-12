mod metadata;
mod resolution;
mod url;
mod versions;

use crate::{error::Error, model::Dependency};

#[cfg(test)]
use crate::fetcher::SourceFetcher;
#[cfg(test)]
use ::url::Url;
#[cfg(test)]
use metadata::{PyPiMetadata, select_locked_artifact};
#[cfg(test)]
use resolution::resolve_python_release;
#[cfg(test)]
use versions::python_compare_versions;

fn resolution_error(dependency: &Dependency, message: impl Into<String>) -> Error {
    Error::Resolution {
        package: dependency.id(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests;
