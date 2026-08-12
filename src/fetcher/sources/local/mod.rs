use std::{
    collections::VecDeque,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use crate::{
    error::{Error, Result},
    model::{Dependency, FetchMetadata},
};

use crate::fetcher::{
    SourceFetcher,
    archive::{ExtractionStats, check_extraction_limits},
    filesystem::TrustedDir,
};

const MAX_LOCAL_PATH_COMPONENTS: usize = 128;

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

        let source = self.snapshot_local_dependency(&source, &declaring_root)?;

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

    /// Copies a confined local dependency into a private workspace before it is
    /// handed to the engine. Keeping a canonical pathname is insufficient: its
    /// final directory can be replaced by a symlink after validation.
    fn snapshot_local_dependency(&self, source: &Path, declaring_root: &Path) -> Result<PathBuf> {
        let source_directory = if let Ok(relative) = source.strip_prefix(declaring_root) {
            let declaring_directory =
                TrustedDir::open(declaring_root).map_err(|source_error| Error::Io {
                    operation: "open declaring package".to_owned(),
                    path: declaring_root.to_owned(),
                    source: source_error,
                })?;
            declaring_directory
                .open_subdirectory(relative)
                .map_err(|source_error| Error::Policy {
                    operation: "local dependency".to_owned(),
                    message: format!(
                        "local dependency is no longer a directory beneath {}: {source_error}",
                        declaring_root.display()
                    ),
                })?
        } else if self.policy.trust_local_input {
            TrustedDir::open(source).map_err(|source_error| Error::Policy {
                operation: "local dependency".to_owned(),
                message: format!(
                    "trusted local dependency is no longer a directory at {}: {source_error}",
                    source.display()
                ),
            })?
        } else {
            return Err(Error::Policy {
                operation: "local dependency".to_owned(),
                message: format!(
                    "could not confine {} beneath {}",
                    source.display(),
                    declaring_root.display()
                ),
            });
        };

        let workspace = self.create_workspace_directory()?;
        let destination = self.create_workspace_subdirectory(
            &workspace,
            Path::new("source"),
            "create local dependency snapshot directory",
        )?;
        let destination_directory =
            TrustedDir::open(&destination).map_err(|source_error| Error::Io {
                operation: "open local dependency snapshot directory".to_owned(),
                path: destination.clone(),
                source: source_error,
            })?;
        if let Err(error) = copy_local_directory(
            source_directory,
            destination_directory,
            source,
            &self.limits,
        ) {
            let _ = fs::remove_dir_all(&workspace);
            return Err(error);
        }
        self.retain_workspace(workspace);
        Ok(destination)
    }
}

fn copy_local_directory(
    source: TrustedDir,
    destination: TrustedDir,
    source_path: &Path,
    limits: &crate::model::EngineLimits,
) -> Result<()> {
    let mut queue = VecDeque::from([(source, destination, source_path.to_owned(), 0usize)]);
    let mut stats = ExtractionStats::default();

    while let Some((source, destination, directory_path, depth)) = queue.pop_front() {
        for name in source
            .list_child_names()
            .map_err(|source_error| Error::Io {
                operation: "list local dependency directory".to_owned(),
                path: directory_path.clone(),
                source: source_error,
            })?
        {
            let child_path = directory_path.join(&name);
            let child_depth = depth + 1;
            if child_depth > MAX_LOCAL_PATH_COMPONENTS {
                return Err(Error::Policy {
                    operation: "local dependency".to_owned(),
                    message: format!(
                        "refusing path deeper than {MAX_LOCAL_PATH_COMPONENTS} components: {}",
                        child_path.display()
                    ),
                });
            }

            stats.files = stats.files.saturating_add(1);
            check_extraction_limits(&stats, limits)?;
            match source.open_subdirectory(&name) {
                Ok(child_source) => {
                    destination
                        .create_dir_all(&name)
                        .map_err(|source_error| Error::Io {
                            operation: "create local dependency snapshot directory".to_owned(),
                            path: child_path.clone(),
                            source: source_error,
                        })?;
                    let child_destination =
                        destination
                            .open_subdirectory(&name)
                            .map_err(|source_error| Error::Io {
                                operation: "open local dependency snapshot directory".to_owned(),
                                path: child_path.clone(),
                                source: source_error,
                            })?;
                    queue.push_back((child_source, child_destination, child_path, child_depth));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotADirectory => {
                    copy_local_file(
                        &source,
                        &destination,
                        &name,
                        &child_path,
                        &mut stats,
                        limits,
                    )?;
                }
                Err(error) => {
                    return Err(Error::Policy {
                        operation: "local dependency".to_owned(),
                        message: format!("refusing unsafe path {}: {error}", child_path.display()),
                    });
                }
            }
        }
    }
    Ok(())
}

fn copy_local_file(
    source: &TrustedDir,
    destination: &TrustedDir,
    name: &Path,
    source_path: &Path,
    stats: &mut ExtractionStats,
    limits: &crate::model::EngineLimits,
) -> Result<()> {
    let mut input = source
        .open_file_no_follow(name)
        .map_err(|source_error| Error::Policy {
            operation: "local dependency".to_owned(),
            message: format!(
                "refusing unsafe path {}: {source_error}",
                source_path.display()
            ),
        })?;
    if !input
        .metadata()
        .map_err(|source_error| Error::Io {
            operation: "inspect local dependency file".to_owned(),
            path: source_path.to_owned(),
            source: source_error,
        })?
        .is_file()
    {
        return Err(Error::Policy {
            operation: "local dependency".to_owned(),
            message: format!("refusing non-regular path {}", source_path.display()),
        });
    }
    let mut output = destination
        .create_new_file(name)
        .map_err(|source_error| Error::Io {
            operation: "create local dependency snapshot file".to_owned(),
            path: source_path.to_owned(),
            source: source_error,
        })?;
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let read = input.read(&mut buffer).map_err(|source_error| Error::Io {
            operation: "read local dependency file".to_owned(),
            path: source_path.to_owned(),
            source: source_error,
        })?;
        if read == 0 {
            break;
        }
        stats.bytes = stats.bytes.saturating_add(read as u64);
        check_extraction_limits(stats, limits)?;
        output
            .write_all(&buffer[..read])
            .map_err(|source_error| Error::Io {
                operation: "write local dependency snapshot file".to_owned(),
                path: source_path.to_owned(),
                source: source_error,
            })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;

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
