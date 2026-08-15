mod cache;
mod metadata;
mod request;
mod resolution;

#[cfg(test)]
use crate::{
    fetcher::SourceFetcher,
    model::{Dependency, Ecosystem},
};
#[cfg(test)]
use request::locked_npm_artifact_url;
#[cfg(test)]
use resolution::{
    npm_compare_versions, npm_package_and_requirement, pin_npm_release, resolve_npm_release,
    select_npm_release, validate_npm_registry_requirement,
};

#[cfg(test)]
mod tests;
