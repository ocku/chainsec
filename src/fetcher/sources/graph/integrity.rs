use std::collections::HashMap;

use url::Url;

use crate::{
    error::{Error, Result},
    fetcher::integrity::verify_integrity,
};

use super::canonical_graph_url;

pub(super) fn verify_graph_module_integrity(
    bytes: &[u8],
    requested_url: &Url,
    effective_url: &Url,
    is_root: bool,
    root_url: &Url,
    expected: Option<&str>,
    remote_integrities: Option<&HashMap<String, String>>,
) -> Result<()> {
    if is_root {
        verify_integrity(bytes, expected, root_url.as_str())?;
    }

    let Some(remote_integrities) = remote_integrities else {
        if !is_root {
            return Err(Error::Policy {
                operation: "Deno graph integrity binding".to_owned(),
                message: format!(
                    "Deno module {requested_url} (effective URL {effective_url}) has no lockfile integrity binding"
                ),
            });
        }
        return Ok(());
    };

    let requested_integrity = remote_integrities
        .get(&canonical_graph_url(requested_url))
        .map(String::as_str);
    let effective_integrity = (requested_url != effective_url)
        .then(|| {
            remote_integrities
                .get(&canonical_graph_url(effective_url))
                .map(String::as_str)
        })
        .flatten();

    if requested_integrity.is_none() && effective_integrity.is_none() {
        return verify_integrity(bytes, None, requested_url.as_str());
    }

    // Deno lockfiles in use may bind either side of a redirect. Prefer the import URL,
    // but validate every declared binding so conflicting entries fail closed.
    if let Some(integrity) = requested_integrity {
        verify_integrity(bytes, Some(integrity), requested_url.as_str())?;
    }
    if let Some(integrity) = effective_integrity {
        verify_integrity(bytes, Some(integrity), effective_url.as_str())?;
    }
    Ok(())
}
