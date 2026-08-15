use std::{collections::HashMap, path::Path};

use url::Url;

use crate::{
    error::{Error, Result},
    fetcher::{
        budget::AcquisitionDeadline,
        filesystem::TrustedDir,
        integrity::{
            sha256_digest_raw_before, verify_integrity_before, verify_integrity_from_sha256_digest,
        },
        network::diagnostic_url,
    },
};

use super::{
    cache_io::{cached_graph_module_filename, read_cached_graph_module_before},
    canonical_graph_url,
    resolution::module_extension,
};

#[derive(Clone, Copy)]
pub(super) struct GraphIntegrity<'a> {
    pub(super) requested_url: &'a Url,
    pub(super) effective_url: &'a Url,
    pub(super) is_root: bool,
    pub(super) root_url: &'a Url,
    pub(super) expected: Option<&'a str>,
    pub(super) remote_integrities: Option<&'a HashMap<String, String>>,
}

#[cfg(test)]
pub(super) fn verify_graph_module_integrity(
    bytes: &[u8],
    requested_url: &Url,
    effective_url: &Url,
    is_root: bool,
    root_url: &Url,
    expected: Option<&str>,
    remote_integrities: Option<&HashMap<String, String>>,
) -> Result<()> {
    let deadline = crate::fetcher::budget::AcquisitionBudget::new(
        std::time::Duration::from_secs(3_600),
        u64::MAX,
    )
    .deadline_guard();
    verify_graph_module_integrity_before(
        bytes,
        GraphIntegrity {
            requested_url,
            effective_url,
            is_root,
            root_url,
            expected,
            remote_integrities,
        },
        &deadline,
    )
}

pub(super) fn verify_graph_module_integrity_before(
    bytes: &[u8],
    binding: GraphIntegrity<'_>,
    deadline: &AcquisitionDeadline,
) -> Result<()> {
    deadline.check()?;
    if binding.is_root {
        verify_integrity_before(bytes, binding.expected, binding.root_url.as_str(), deadline)?;
    }

    let Some(remote_integrities) = binding.remote_integrities else {
        if !binding.is_root {
            return Err(Error::Policy {
                operation: "Deno graph integrity binding".to_owned(),
                message: format!(
                    "Deno module {} (effective URL {}) has no lockfile integrity binding",
                    binding.requested_url, binding.effective_url
                ),
            });
        }
        return Ok(());
    };

    let requested_integrity = remote_integrities
        .get(&canonical_graph_url(binding.requested_url))
        .map(String::as_str);
    let effective_integrity = (binding.requested_url != binding.effective_url)
        .then(|| {
            remote_integrities
                .get(&canonical_graph_url(binding.effective_url))
                .map(String::as_str)
        })
        .flatten();

    if requested_integrity.is_none() && effective_integrity.is_none() {
        return verify_integrity_before(bytes, None, binding.requested_url.as_str(), deadline);
    }

    // Deno lockfiles in use may bind either side of a redirect. Prefer the import URL,
    // but validate every declared binding so conflicting entries fail closed.
    if let Some(integrity) = requested_integrity {
        verify_integrity_before(
            bytes,
            Some(integrity),
            binding.requested_url.as_str(),
            deadline,
        )?;
    }
    if let Some(integrity) = effective_integrity {
        verify_integrity_before(
            bytes,
            Some(integrity),
            binding.effective_url.as_str(),
            deadline,
        )?;
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn verify_graph_module_integrity_from_digest(
    digest: &[u8; 32],
    requested_url: &Url,
    effective_url: &Url,
    is_root: bool,
    root_url: &Url,
    expected: Option<&str>,
    remote_integrities: Option<&HashMap<String, String>>,
) -> Result<Option<()>> {
    let deadline = crate::fetcher::budget::AcquisitionBudget::new(
        std::time::Duration::from_secs(3_600),
        u64::MAX,
    )
    .deadline_guard();
    verify_graph_module_integrity_from_digest_before(
        digest,
        GraphIntegrity {
            requested_url,
            effective_url,
            is_root,
            root_url,
            expected,
            remote_integrities,
        },
        &deadline,
    )
}

pub(super) fn verify_graph_module_integrity_from_digest_before(
    digest: &[u8; 32],
    binding: GraphIntegrity<'_>,
    deadline: &AcquisitionDeadline,
) -> Result<Option<()>> {
    deadline.check()?;
    if binding.is_root
        && verify_integrity_from_sha256_digest(
            digest,
            binding.expected,
            binding.root_url.as_str(),
            deadline,
        )?
        .is_none()
    {
        return Ok(None);
    }

    let Some(remote_integrities) = binding.remote_integrities else {
        if !binding.is_root {
            return Err(Error::Policy {
                operation: "Deno graph integrity binding".to_owned(),
                message: format!(
                    "Deno module {} (effective URL {}) has no lockfile integrity binding",
                    binding.requested_url, binding.effective_url
                ),
            });
        }
        return Ok(Some(()));
    };

    let requested_integrity = remote_integrities
        .get(&canonical_graph_url(binding.requested_url))
        .map(String::as_str);
    let effective_integrity = (binding.requested_url != binding.effective_url)
        .then(|| {
            remote_integrities
                .get(&canonical_graph_url(binding.effective_url))
                .map(String::as_str)
        })
        .flatten();

    if requested_integrity.is_none() && effective_integrity.is_none() {
        return verify_integrity_from_sha256_digest(
            digest,
            None,
            binding.requested_url.as_str(),
            deadline,
        );
    }

    // Deno lockfiles in use may bind either side of a redirect. Prefer the import URL,
    // but validate every declared binding so conflicting entries fail closed.
    if let Some(integrity) = requested_integrity
        && verify_integrity_from_sha256_digest(
            digest,
            Some(integrity),
            binding.requested_url.as_str(),
            deadline,
        )?
        .is_none()
    {
        return Ok(None);
    }
    if let Some(integrity) = effective_integrity
        && verify_integrity_from_sha256_digest(
            digest,
            Some(integrity),
            binding.effective_url.as_str(),
            deadline,
        )?
        .is_none()
    {
        return Ok(None);
    }
    Ok(Some(()))
}

pub(super) fn verify_materialized_module_bytes(
    source_root: &TrustedDir,
    source: &Path,
    canonical: &str,
    max_archive_size: u64,
    stored_digest: &[u8; 32],
    binding: GraphIntegrity<'_>,
    deadline: &AcquisitionDeadline,
) -> Result<()> {
    deadline.check()?;
    let extension = module_extension(binding.effective_url);
    let filename = cached_graph_module_filename(canonical, extension);
    let bytes = read_cached_graph_module_before(
        source_root,
        source,
        &filename,
        max_archive_size,
        deadline,
    )?;
    let recomputed = sha256_digest_raw_before(&bytes, deadline)?;
    if recomputed != *stored_digest {
        return Err(Error::Fetch {
            package: "artifact".to_owned(),
            source_url: diagnostic_url(binding.requested_url),
            message: "integrity verification failed or uses an unsupported format".to_owned(),
        });
    }
    verify_graph_module_integrity_before(&bytes, binding, deadline)
}
