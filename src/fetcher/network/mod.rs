mod artifacts;
mod download;
mod url_policy;

pub(in crate::fetcher) use download::{NetworkBudget, diagnostic_url};

#[cfg(test)]
pub(in crate::fetcher) use artifacts::{artifact_url_is_lockfile_defined, jsr_package_name};

#[cfg(test)]
mod tests;
