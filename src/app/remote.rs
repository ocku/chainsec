use chainsec::model::{Dependency, Ecosystem};

use super::cli::Cli;

pub(super) fn add_allowed_host(cli: &mut Cli) -> chainsec::Result<()> {
    if !cli.online {
        return Ok(());
    }
    let Some(remote) = &cli.remote else {
        return Ok(());
    };

    let dependency = dependency(remote)?;
    let url = if let Some(source_url) = dependency.source_url {
        url::Url::parse(&source_url).map_err(|error| chainsec::Error::InvalidConfiguration {
            message: format!("invalid remote source URL {source_url:?}: {error}"),
        })?
    } else {
        match dependency.ecosystem {
            Ecosystem::Npm => cli.artifactories.npm_metadata_url(&dependency.name)?,
            Ecosystem::Python => cli.artifactories.pypi_release_url(&dependency.name, None)?,
            Ecosystem::Deno => cli
                .artifactories
                .jsr_package_metadata_url(&dependency.name)?,
        }
    };
    let host = url
        .host_str()
        .ok_or_else(|| chainsec::Error::InvalidConfiguration {
            message: format!("remote source URL has no host: {url}"),
        })?;

    if !cli.allowed_hosts.iter().any(|allowed| allowed == host) {
        cli.allowed_hosts.push(host.to_owned());
    }
    Ok(())
}

pub(super) fn dependency(specifier: &str) -> chainsec::Result<Dependency> {
    let (source, package) =
        specifier
            .split_once(':')
            .ok_or_else(|| chainsec::Error::InvalidConfiguration {
                message: "--remote must be SOURCE:PACKAGE".to_owned(),
            })?;
    if package.is_empty() {
        return Err(chainsec::Error::InvalidConfiguration {
            message: "--remote package must not be empty".to_owned(),
        });
    }

    match source {
        "npm" => {
            let name = package
                .rsplit_once('@')
                .filter(|(name, _)| !name.is_empty())
                .map_or(package, |(name, _)| name);
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
            if !package.starts_with('@') || !package.contains('/') {
                return Err(chainsec::Error::InvalidConfiguration {
                    message: "JSR remote package must be scoped, for example jsr:@std/fs"
                        .to_owned(),
                });
            }
            Ok(Dependency::declared(
                Ecosystem::Deno,
                package,
                format!("jsr:{package}"),
            ))
        }
        "github" => github_dependency(package),
        _ => Err(chainsec::Error::InvalidConfiguration {
            message: format!("unsupported remote source {source:?}; use github, pypi, jsr, or npm"),
        }),
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
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn adds_configured_hosts_for_all_remote_sources() {
        let revision = "0123456789012345678901234567890123456789";
        let github_remote = format!("github:owner/repository@{revision}");
        for (remote, host) in [
            ("npm:express", "npm.example.test"),
            ("pypi:urllib3", "pypi.example.test"),
            ("jsr:@std/fs", "jsr.example.test"),
            (github_remote.as_str(), "codeload.github.com"),
        ] {
            let mut cli =
                Cli::try_parse_from(["chainsec", "--online", "--remote", remote]).unwrap();
            cli.artifactories = chainsec::ArtifactRepositories::new(
                "https://npm.example.test/registry",
                "https://pypi.example.test/simple",
                "https://jsr.example.test/registry",
            )
            .unwrap();

            add_allowed_host(&mut cli).unwrap();

            assert_eq!(cli.allowed_hosts, vec![host.to_owned()]);
        }
    }

    #[test]
    fn parses_registry_remote_roots() {
        let npm = dependency("npm:express@0.1.0").unwrap();
        assert_eq!(npm.ecosystem, Ecosystem::Npm);
        assert_eq!(npm.name, "express");
        assert_eq!(npm.requirement, "npm:express@0.1.0");

        let pypi = dependency("pypi:urllib3").unwrap();
        assert_eq!(pypi.ecosystem, Ecosystem::Python);
        assert_eq!(pypi.name, "urllib3");

        let jsr = dependency("jsr:@std/fs").unwrap();
        assert_eq!(jsr.ecosystem, Ecosystem::Deno);
        assert_eq!(jsr.requirement, "jsr:@std/fs");
    }

    #[test]
    fn parses_pinned_github_remote_root() {
        let revision = "0123456789012345678901234567890123456789";
        let dependency = dependency(&format!("github:owner/repository@{revision}")).unwrap();

        assert!(dependency.is_pinned_github());
        assert_eq!(dependency.resolved_version.as_deref(), Some(revision));
    }

    #[test]
    fn rejects_unpinned_github_remote_root() {
        let error = dependency("github:owner/repository@main").unwrap_err();
        assert!(error.to_string().contains("40_HEX_COMMIT"));
    }
}
