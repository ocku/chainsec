use crate::model::{Dependency, Ecosystem};

/// Parses a remote package specifier into a [`Dependency`].
///
/// Supported formats:
/// - `npm:[@scope/]name[@version]`
/// - `pypi:name[version_spec]`
/// - `jsr:@scope/name[@version]`
/// - `github:owner/repo@40_HEX_COMMIT`
pub fn parse_remote_package(specifier: &str) -> crate::Result<Dependency> {
    let (source, package) =
        specifier
            .split_once(':')
            .ok_or_else(|| crate::Error::InvalidConfiguration {
                message: "remote package must be SOURCE:PACKAGE".to_owned(),
            })?;
    if package.is_empty() {
        return Err(crate::Error::InvalidConfiguration {
            message: "remote package must not be empty".to_owned(),
        });
    }

    match source {
        "npm" => parse_npm(package),
        "pypi" => parse_pypi(package),
        "jsr" => parse_jsr(package),
        "github" => parse_github(package),
        _ => Err(crate::Error::InvalidConfiguration {
            message: format!("unsupported remote source {source:?}; use github, pypi, jsr, or npm"),
        }),
    }
}

fn parse_npm(package: &str) -> crate::Result<Dependency> {
    let name = package
        .rsplit_once('@')
        .filter(|(name, _)| !name.is_empty())
        .map_or(package, |(name, _)| name);
    if !valid_npm_package_name(name) {
        return Err(crate::Error::InvalidConfiguration {
            message: "npm remote package must contain a valid package name".to_owned(),
        });
    }
    Ok(Dependency::declared(
        Ecosystem::Npm,
        name,
        format!("npm:{package}"),
    ))
}

fn parse_pypi(package: &str) -> crate::Result<Dependency> {
    let name = package
        .split(['<', '>', '=', '!', '~', ';', '[', ' '])
        .next()
        .unwrap_or_default();
    if name.is_empty() {
        return Err(crate::Error::InvalidConfiguration {
            message: "PyPI remote package must start with a package name".to_owned(),
        });
    }
    Ok(Dependency::declared(Ecosystem::Python, name, package))
}

fn parse_jsr(package: &str) -> crate::Result<Dependency> {
    let name = package
        .rsplit_once('@')
        .filter(|(name, _)| !name.is_empty())
        .map_or(package, |(name, _)| name);
    if !name.starts_with('@') || !name.contains('/') {
        return Err(crate::Error::InvalidConfiguration {
            message: "JSR remote package must be scoped, for example jsr:@std/fs".to_owned(),
        });
    }
    Ok(Dependency::declared(
        Ecosystem::Deno,
        name,
        format!("jsr:{package}"),
    ))
}

fn parse_github(package: &str) -> crate::Result<Dependency> {
    let (repository, revision) = package
        .rsplit_once('@')
        .or_else(|| package.rsplit_once('#'))
        .ok_or_else(|| crate::Error::InvalidConfiguration {
            message: "GitHub remote package must be OWNER/REPO@40_HEX_COMMIT".to_owned(),
        })?;
    if repository.split('/').count() != 2
        || repository.split('/').any(str::is_empty)
        || revision.len() != 40
        || !revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(crate::Error::InvalidConfiguration {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_npm_package() {
        let dep = parse_remote_package("npm:express").unwrap();
        assert_eq!(dep.ecosystem, Ecosystem::Npm);
        assert_eq!(dep.name, "express");
    }

    #[test]
    fn parses_scoped_npm_package() {
        let dep = parse_remote_package("npm:@scope/package@1.0.0").unwrap();
        assert_eq!(dep.ecosystem, Ecosystem::Npm);
        assert_eq!(dep.name, "@scope/package");
    }

    #[test]
    fn parses_pypi_package() {
        let dep = parse_remote_package("pypi:requests>=2.0").unwrap();
        assert_eq!(dep.ecosystem, Ecosystem::Python);
        assert_eq!(dep.name, "requests");
    }

    #[test]
    fn parses_jsr_package() {
        let dep = parse_remote_package("jsr:@std/fs@1.0.0").unwrap();
        assert_eq!(dep.ecosystem, Ecosystem::Deno);
        assert_eq!(dep.name, "@std/fs");
    }

    #[test]
    fn parses_github_package() {
        let dep =
            parse_remote_package("github:owner/repo@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();
        assert_eq!(dep.ecosystem, Ecosystem::Npm);
        assert_eq!(dep.name, "owner/repo");
        assert!(dep.source_url.is_some());
    }
}
