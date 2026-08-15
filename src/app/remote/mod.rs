use chainsec::model::{Dependency, Ecosystem};

use super::cli::AnalysisOptions;

pub(super) fn add_allowed_host(
    options: &mut AnalysisOptions,
    package: &str,
) -> chainsec::Result<()> {
    let dependency = dependency(package)?;
    let url = if let Some(source_url) = dependency.source_url {
        url::Url::parse(&source_url).map_err(|error| chainsec::Error::InvalidConfiguration {
            message: format!("invalid remote source URL {source_url:?}: {error}"),
        })?
    } else {
        match dependency.ecosystem {
            Ecosystem::Npm => options.artifactories.npm_metadata_url(&dependency.name)?,
            Ecosystem::Python => options
                .artifactories
                .pypi_release_url(&dependency.name, None)?,
            Ecosystem::Deno => options
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
    if dependency.ecosystem == Ecosystem::Python {
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

pub(super) fn dependency(specifier: &str) -> chainsec::Result<Dependency> {
    let (source, package) =
        specifier
            .split_once(':')
            .ok_or_else(|| chainsec::Error::InvalidConfiguration {
                message: "remote package must be SOURCE:PACKAGE".to_owned(),
            })?;
    if package.is_empty() {
        return Err(chainsec::Error::InvalidConfiguration {
            message: "remote package must not be empty".to_owned(),
        });
    }

    match source {
        "npm" => {
            let name = package
                .rsplit_once('@')
                .filter(|(name, _)| !name.is_empty())
                .map_or(package, |(name, _)| name);
            if !valid_npm_package_name(name) {
                return Err(chainsec::Error::InvalidConfiguration {
                    message: "npm remote package must contain a valid package name".to_owned(),
                });
            }
            Ok(Dependency::declared(
                Ecosystem::Npm,
                name,
                format!("npm:{package}"),
            ))
        }
        "pypi" => {
            let name = package
                .split(['<', '>', '=', '!', '~', ';', '[', ' '])
                .next()
                .unwrap_or_default();
            if name.is_empty() {
                return Err(chainsec::Error::InvalidConfiguration {
                    message: "PyPI remote package must start with a package name".to_owned(),
                });
            }
            Ok(Dependency::declared(Ecosystem::Python, name, package))
        }
        "jsr" => {
            let name = package
                .rsplit_once('@')
                .filter(|(name, _)| !name.is_empty())
                .map_or(package, |(name, _)| name);
            if !name.starts_with('@') || !name.contains('/') {
                return Err(chainsec::Error::InvalidConfiguration {
                    message: "JSR remote package must be scoped, for example jsr:@std/fs"
                        .to_owned(),
                });
            }
            Ok(Dependency::declared(
                Ecosystem::Deno,
                name,
                format!("jsr:{package}"),
            ))
        }
        "github" => github_dependency(package),
        _ => Err(chainsec::Error::InvalidConfiguration {
            message: format!("unsupported remote source {source:?}; use github, pypi, jsr, or npm"),
        }),
    }
}

fn valid_npm_package_name(name: &str) -> bool {
    let valid_part = |part: &str| {
        part.bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    };

    if let Some(scoped) = name.strip_prefix('@') {
        let Some((scope, package)) = scoped.split_once('/') else {
            return false;
        };
        !package.contains('/') && valid_part(scope) && valid_part(package)
    } else {
        valid_part(name) && !name.contains('/')
    }
}

fn github_dependency(package: &str) -> chainsec::Result<Dependency> {
    let (repository, revision) = package
        .rsplit_once('@')
        .or_else(|| package.rsplit_once('#'))
        .ok_or_else(|| chainsec::Error::InvalidConfiguration {
            message: "GitHub remote package must be OWNER/REPO@40_HEX_COMMIT".to_owned(),
        })?;
    if repository.split('/').count() != 2
        || repository.split('/').any(str::is_empty)
        || revision.len() != 40
        || !revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(chainsec::Error::InvalidConfiguration {
            message: "GitHub remote package must be OWNER/REPO@40_HEX_COMMIT".to_owned(),
        });
    }

    let mut dependency = Dependency::declared(Ecosystem::Npm, repository, package);
    dependency.resolved_version = Some(revision.to_owned());
    dependency.source_url = Some(format!(
        "https://codeload.github.com/{repository}/tar.gz/{revision}"
    ));
    Ok(dependency)
}

#[cfg(test)]
mod tests;
