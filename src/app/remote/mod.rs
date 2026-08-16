use chainsec::model::parse_remote_package;

use super::cli::AnalysisOptions;

pub(super) fn add_allowed_host(
    options: &mut AnalysisOptions,
    package: &str,
) -> chainsec::Result<()> {
    let dependency = parse_remote_package(package)?;
    let url = if let Some(source_url) = dependency.source_url {
        url::Url::parse(&source_url).map_err(|error| chainsec::Error::InvalidConfiguration {
            message: format!("invalid remote source URL {source_url:?}: {error}"),
        })?
    } else {
        match dependency.ecosystem {
            chainsec::model::Ecosystem::Npm => {
                options.artifactories.npm_metadata_url(&dependency.name)?
            }
            chainsec::model::Ecosystem::Python => options
                .artifactories
                .pypi_release_url(&dependency.name, None)?,
            chainsec::model::Ecosystem::Deno => options
                .artifactories
                .jsr_package_metadata_url(&dependency.name)?,
        }
    };
    let host = url
        .host_str()
        .ok_or_else(|| chainsec::Error::InvalidConfiguration {
            message: format!("remote source URL has no host: {url}"),
        })?;

    let mut hosts = vec![host];
    if dependency.ecosystem == chainsec::model::Ecosystem::Python {
        let artifact_host = options
            .artifactories
            .pypi_artifact_base_url()
            .host_str()
            .expect("validated PyPI artifact URL has a host");
        hosts.push(artifact_host);
    }
    for host in hosts {
        if !options.allowed_hosts.iter().any(|allowed| allowed == host) {
            options.allowed_hosts.push(host.to_owned());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
