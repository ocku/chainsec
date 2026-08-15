use std::{fs, path::Path};

use crate::error::{Error, Result};

use super::{CacheStaging, SourceFetcher, filesystem::TrustedDir, types::ScanWorkspace};

pub(super) fn restrict_workspace_directory(path: &Path, operation: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
            Error::Io {
                operation: operation.to_owned(),
                path: path.to_owned(),
                source,
            }
        })?;
    }
    #[cfg(not(unix))]
    let _ = (path, operation);
    Ok(())
}

impl Drop for ScanWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl SourceFetcher {
    pub(in crate::fetcher) fn retain_workspace(&self, root: std::path::PathBuf) {
        self.workspaces
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(ScanWorkspace { root });
    }

    /// Creates an owner-only workspace outside cache storage. `tempfile` uses
    /// randomized, atomic creation; Unix writes beneath it remain descriptor-relative
    /// through `TrustedDir`, while non-Unix platforms provide best-effort confinement.
    pub(in crate::fetcher) fn create_workspace_directory(&self) -> Result<std::path::PathBuf> {
        let workspace = tempfile::Builder::new()
            .prefix("workspace-")
            .tempdir_in(&self.workspace_root_path)
            .map_err(|source| Error::Io {
                operation: "create private scan workspace".to_owned(),
                path: self.workspace_root_path.clone(),
                source,
            })?
            .keep();
        restrict_workspace_directory(&workspace, "restrict private scan workspace")?;
        Ok(workspace)
    }

    pub(in crate::fetcher) fn create_workspace_subdirectory(
        &self,
        workspace: &Path,
        relative: &Path,
        operation: &str,
    ) -> Result<std::path::PathBuf> {
        let path = workspace.join(relative);
        TrustedDir::open(workspace)
            .and_then(|root| root.create_dir_all(relative))
            .map_err(|source| Error::Io {
                operation: operation.to_owned(),
                path: path.clone(),
                source,
            })?;
        Ok(path)
    }

    /// Cache publications are direct children of the pinned root, so their final
    /// rename into an ecosystem remains atomic without resolving the cache path again.
    pub(in crate::fetcher) fn create_cache_staging_directory(
        &self,
        prefix: &str,
    ) -> Result<CacheStaging> {
        let (name, directory) = self
            .cache_root
            .create_unique_child_dir(Path::new(prefix))
            .map_err(|source| Error::Io {
                operation: "create temporary cache entry".to_owned(),
                path: self.cache.clone(),
                source,
            })?;
        Ok(CacheStaging {
            path: self.cache.join(&name),
            name,
            directory,
        })
    }
}
