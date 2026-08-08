use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::{
    error::{Error, Result},
    model::{Dependency, FetchMetadata},
};

use crate::fetcher::SourceFetcher;

impl SourceFetcher {
    pub(in crate::fetcher) fn fetch_local_dependency(
        &self,
        dependency: &Dependency,
        declared_from: &Path,
    ) -> Result<FetchMetadata> {
        let raw_path = local_dependency_path(dependency)?;
        let candidate = if raw_path.is_absolute() {
            raw_path.clone()
        } else {
            declared_from.join(&raw_path)
        };
        let source = fs::canonicalize(&candidate).map_err(|source| Error::Io {
            operation: "canonicalize local dependency".to_owned(),
            path: candidate,
            source,
        })?;
        let declaring_root = fs::canonicalize(declared_from).map_err(|source| Error::Io {
            operation: "canonicalize declaring package".to_owned(),
            path: declared_from.to_owned(),
            source,
        })?;
        if !self.policy.trust_local_input && !source.starts_with(&declaring_root) {
            return Err(Error::Policy {
                operation: "local dependency".to_owned(),
                message: format!(
                    "{} escapes {}; use --trust-local-input to allow it",
                    source.display(),
                    declaring_root.display()
                ),
            });
        }

        Ok(FetchMetadata {
            source,
            package_id: dependency.id(),
            resolved_version: dependency
                .resolved_version
                .clone()
                .unwrap_or_else(|| "local".to_owned()),
            digest: "local-unverified".to_owned(),
            source_url: format!("file:{}", raw_path.display()),
            cache_hit: false,
        })
    }
}

fn local_dependency_path(dependency: &Dependency) -> Result<PathBuf> {
    if let Some(source_url) = dependency
        .source_url
        .as_deref()
        .filter(|url| url.starts_with("file:"))
    {
        let url = url::Url::parse(source_url).map_err(|error| Error::Resolution {
            package: dependency.id(),
            message: format!("invalid local dependency URL: {error}"),
        })?;
        return url.to_file_path().map_err(|()| Error::Resolution {
            package: dependency.id(),
            message: "local dependency URL is not a valid filesystem path".to_owned(),
        });
    }

    Ok(PathBuf::from(
        dependency
            .requirement
            .strip_prefix("file:")
            .unwrap_or(&dependency.requirement),
    ))
}
