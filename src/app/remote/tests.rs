use super::*;
use crate::app::cli::{Cli, Command, RemoteSubcommand};
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
        let cli = Cli::try_parse_from(["chainsec", "remote", "scan", remote]).unwrap();
        let Command::Remote(remote_command) = cli.command else {
            panic!("expected remote command")
        };
        let RemoteSubcommand::Scan(mut scan) = remote_command.command else {
            panic!("expected remote scan command")
        };
        scan.options.artifactories = chainsec::ArtifactRepositories::new(
            "https://npm.example.test/registry",
            "https://pypi.example.test/simple",
            "https://jsr.example.test/registry",
        )
        .unwrap();

        add_allowed_host(&mut scan.options, &scan.package).unwrap();

        assert_eq!(scan.options.allowed_hosts, vec![host.to_owned()]);
    }
}

#[test]
fn adds_official_pypi_artifact_host() {
    let cli = Cli::try_parse_from(["chainsec", "remote", "scan", "pypi:pandas"]).unwrap();
    let Command::Remote(remote_command) = cli.command else {
        panic!("expected remote command")
    };
    let RemoteSubcommand::Scan(mut scan) = remote_command.command else {
        panic!("expected remote scan command")
    };

    add_allowed_host(&mut scan.options, &scan.package).unwrap();

    assert_eq!(
        scan.options.allowed_hosts,
        vec!["pypi.org".to_owned(), "files.pythonhosted.org".to_owned()]
    );
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
    assert_eq!(jsr.name, "@std/fs");
    assert_eq!(jsr.requirement, "jsr:@std/fs");

    let versioned_jsr = dependency("jsr:@std/fs@1.0.0").unwrap();
    assert_eq!(versioned_jsr.name, "@std/fs");
    assert_eq!(versioned_jsr.requirement, "jsr:@std/fs@1.0.0");
}

#[test]
fn rejects_malformed_npm_remote_roots_before_fetching() {
    for specifier in [
        "npm:@1.0.0",
        "npm:@scope",
        "npm:bad/name@1.0.0",
        "npm:.hidden",
    ] {
        let error = dependency(specifier).unwrap_err();
        assert!(
            error.to_string().contains("valid package name"),
            "{specifier}"
        );
    }
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
