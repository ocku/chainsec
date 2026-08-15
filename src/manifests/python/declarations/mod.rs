use std::path::Path;

#[cfg(test)]
use toml::Value as TomlValue;

#[cfg(test)]
use super::matching::normalize;
use crate::{error::Result, manifests::shared::BoundedDependencyCollector, model::Dependency};

mod pep621;
mod pipfile;
mod poetry;
mod shared;

pub(in crate::manifests) use pipfile::parse_pipfile_with_limit;
#[cfg(test)]
use poetry::{poetry_dependency, poetry_requirement};
#[allow(unused_imports)]
pub(super) use shared::dependency_from_requirement;

#[cfg(test)]
pub(in crate::manifests) fn parse(path: &Path) -> Result<Vec<Dependency>> {
    parse_with_limit(path, crate::model::EngineLimits::default().max_packages)
}

pub(in crate::manifests) fn parse_with_limit(
    path: &Path,
    max_packages: usize,
) -> Result<Vec<Dependency>> {
    let value = shared::parse_toml(path)?;
    let mut dependencies = BoundedDependencyCollector::new(max_packages);

    pep621::parse_project_dependencies(path, &value, &mut dependencies)?;
    pep621::parse_dependency_groups(path, &value, &mut dependencies)?;
    poetry::parse_poetry_dependencies(path, &value, &mut dependencies)?;
    Ok(dependencies.into_dependencies())
}

#[cfg(test)]
mod tests;
