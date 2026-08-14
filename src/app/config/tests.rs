use clap::{CommandFactory, FromArgMatches};

use super::{apply, files::FileConfig};
use crate::app::cli::{Cli, Command, RemoteSubcommand};

#[test]
fn network_acquisition_limits_load_from_toml_unless_cli_overrides_them() {
    let matches = Cli::command()
        .try_get_matches_from([
            "chainsec",
            "scan",
            "--max-network-requests",
            "7",
            "--max-redirect-hops",
            "9",
        ])
        .unwrap();
    let cli = Cli::from_arg_matches(&matches).unwrap();
    let Command::Scan(mut scan) = cli.command else {
        panic!("expected scan command")
    };
    let config: FileConfig = toml::from_str(
        "max_network_requests = 11\nmax_redirect_hops = 13\nrequest_timeout_seconds = 17\nmax_acquisition_seconds = 19",
    )
    .unwrap();
    let command_matches = matches.subcommand_matches("scan").unwrap();

    apply(&mut scan.options, config, None, command_matches, false).unwrap();

    assert_eq!(scan.options.max_network_requests, 7);
    assert_eq!(scan.options.max_redirect_hops, 9);
    assert_eq!(scan.options.request_timeout_seconds, 17);
    assert_eq!(scan.options.max_acquisition_seconds, 19);
}

#[test]
fn source_file_limit_loads_from_toml_unless_cli_overrides_it() {
    let matches = Cli::command()
        .try_get_matches_from(["chainsec", "scan", "--max-source-files", "7"])
        .unwrap();
    let cli = Cli::from_arg_matches(&matches).unwrap();
    let Command::Scan(mut scan) = cli.command else {
        panic!("expected scan command")
    };
    let config: FileConfig = toml::from_str("max_source_files = 11").unwrap();
    let command_matches = matches.subcommand_matches("scan").unwrap();

    apply(&mut scan.options, config, None, command_matches, false).unwrap();

    assert_eq!(scan.options.max_source_files, 7);
}

#[test]
fn zero_positive_numeric_values_are_rejected_from_configuration() {
    for field in ["max_network_requests", "threads"] {
        let matches = Cli::command()
            .try_get_matches_from(["chainsec", "scan"])
            .unwrap();
        let cli = Cli::from_arg_matches(&matches).unwrap();
        let Command::Scan(mut scan) = cli.command else {
            panic!("expected scan command")
        };
        let config: FileConfig = toml::from_str(&format!("{field} = 0")).unwrap();
        let command_matches = matches.subcommand_matches("scan").unwrap();

        let error = apply(&mut scan.options, config, None, command_matches, false).unwrap_err();

        let expected = match field {
            "threads" => "threads must be between 1 and 64",
            "max_network_requests" => "max_network_requests must be at least 1",
            _ => unreachable!("tested fields are explicit"),
        };
        assert!(error.to_string().contains(expected));
    }
}

#[test]
fn invalid_configured_thread_values_are_ignored_when_cli_overridden() {
    let matches = Cli::command()
        .try_get_matches_from(["chainsec", "scan", "--threads", "4"])
        .unwrap();
    let cli = Cli::from_arg_matches(&matches).unwrap();
    let Command::Scan(mut scan) = cli.command else {
        panic!("expected scan command")
    };
    for value in [0, 65] {
        let config: FileConfig = toml::from_str(&format!("threads = {value}")).unwrap();
        let command_matches = matches.subcommand_matches("scan").unwrap();

        apply(&mut scan.options, config, None, command_matches, false).unwrap();

        assert_eq!(scan.options.threads, 4);
    }
}

#[test]
fn oversized_configured_threads_are_rejected() {
    let matches = Cli::command()
        .try_get_matches_from(["chainsec", "scan"])
        .unwrap();
    let cli = Cli::from_arg_matches(&matches).unwrap();
    let Command::Scan(mut scan) = cli.command else {
        panic!("expected scan command")
    };
    let config: FileConfig = toml::from_str("threads = 65").unwrap();
    let command_matches = matches.subcommand_matches("scan").unwrap();

    let error = apply(&mut scan.options, config, None, command_matches, false).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("threads must be between 1 and 64")
    );
}

#[test]
fn offline_scan_accepts_configured_credential_without_its_environment_variable() {
    let matches = Cli::command()
        .try_get_matches_from(["chainsec", "scan"])
        .unwrap();
    let cli = Cli::from_arg_matches(&matches).unwrap();
    let Command::Scan(mut scan) = cli.command else {
        panic!("expected scan command");
    };
    let variable = format!("CHAINSEC_TEST_MISSING_TOKEN_{}", std::process::id());
    let config: FileConfig = toml::from_str(&format!(
        r#"
        [artifactories.npm]
        metadata_base_url = "https://npm.example.test/registry"

        [artifactories.npm.credential]
        scope = "https://npm.example.test/registry/private"
        bearer_token_env = "{variable}"
        "#
    ))
    .unwrap();
    let command_matches = matches.subcommand_matches("scan").unwrap();

    apply(&mut scan.options, config, None, command_matches, false).unwrap();

    assert!(!scan.options.online);
}

#[test]
fn remote_force_online_allows_all_configured_repository_hosts() {
    let matches = Cli::command()
        .try_get_matches_from(["chainsec", "remote", "scan", "npm:express"])
        .unwrap();
    let cli = Cli::from_arg_matches(&matches).unwrap();
    let Command::Remote(remote) = cli.command else {
        panic!("expected remote command")
    };
    let RemoteSubcommand::Scan(mut scan) = remote.command else {
        panic!("expected remote scan command")
    };
    let config: FileConfig = toml::from_str(
        r#"
        online = false

        [artifactories.npm]
        metadata_base_url = "https://npm.example.test/registry"

        [artifactories.jsr]
        metadata_base_url = "https://jsr.example.test/registry"
        "#,
    )
    .unwrap();
    let command_matches = matches
        .subcommand_matches("remote")
        .and_then(|matches| matches.subcommand_matches("scan"))
        .unwrap();

    apply(&mut scan.options, config, None, command_matches, true).unwrap();

    assert!(scan.options.online);
    assert_eq!(
        scan.options.allowed_hosts,
        ["npm.example.test", "jsr.example.test"]
    );
}

#[test]
fn pypi_artifact_base_override_allows_both_configured_hosts_in_any_field_order() {
    for config_source in [
        r#"
        [artifactories.pypi]
        metadata_base_url = "https://metadata.example.test/pypi"
        artifact_base_url = "https://artifacts.example.test/packages"
        "#,
        r#"
        [artifactories.pypi]
        artifact_base_url = "https://artifacts.example.test/packages"
        metadata_base_url = "https://metadata.example.test/pypi"
        "#,
    ] {
        let matches = Cli::command()
            .try_get_matches_from(["chainsec", "remote", "scan", "pypi:example"])
            .unwrap();
        let cli = Cli::from_arg_matches(&matches).unwrap();
        let Command::Remote(remote) = cli.command else {
            panic!("expected remote command")
        };
        let RemoteSubcommand::Scan(mut scan) = remote.command else {
            panic!("expected remote scan command")
        };
        let command_matches = matches
            .subcommand_matches("remote")
            .and_then(|matches| matches.subcommand_matches("scan"))
            .unwrap();

        apply(
            &mut scan.options,
            toml::from_str(config_source).unwrap(),
            None,
            command_matches,
            true,
        )
        .unwrap();

        assert_eq!(
            scan.options.allowed_hosts,
            ["metadata.example.test", "artifacts.example.test"]
        );
        assert_eq!(
            scan.options
                .artifactories
                .pypi_release_url("example", Some("1.0.0"))
                .unwrap()
                .as_str(),
            "https://metadata.example.test/pypi/example/1.0.0/json"
        );
        assert_eq!(
            scan.options.artifactories.pypi_artifact_base_url().as_str(),
            "https://artifacts.example.test/packages/"
        );
    }
}

#[test]
fn remote_accepts_explicit_online_flag() {
    let matches = Cli::command()
        .try_get_matches_from(["chainsec", "remote", "scan", "npm:express", "--online"])
        .unwrap();
    let cli = Cli::from_arg_matches(&matches).unwrap();
    let Command::Remote(remote) = cli.command else {
        panic!("expected remote command")
    };
    let RemoteSubcommand::Scan(mut scan) = remote.command else {
        panic!("expected remote scan command")
    };
    let command_matches = matches
        .subcommand_matches("remote")
        .and_then(|matches| matches.subcommand_matches("scan"))
        .unwrap();

    apply(
        &mut scan.options,
        FileConfig::default(),
        None,
        command_matches,
        true,
    )
    .unwrap();

    assert!(scan.options.online);
}

#[test]
fn verbose_rejects_machine_format_from_cli() {
    let matches = Cli::command()
        .try_get_matches_from(["chainsec", "scan", "--verbose", "--format", "json"])
        .unwrap();
    let cli = Cli::from_arg_matches(&matches).unwrap();
    let Command::Scan(mut scan) = cli.command else {
        panic!("expected scan command")
    };
    let command_matches = matches.subcommand_matches("scan").unwrap();

    let error = apply(
        &mut scan.options,
        FileConfig::default(),
        None,
        command_matches,
        false,
    )
    .unwrap_err();

    assert!(error.to_string().contains("--verbose is only valid"));
}

#[test]
fn verbose_rejects_machine_format_from_configuration() {
    let matches = Cli::command()
        .try_get_matches_from(["chainsec", "scan", "--verbose"])
        .unwrap();
    let cli = Cli::from_arg_matches(&matches).unwrap();
    let Command::Scan(mut scan) = cli.command else {
        panic!("expected scan command")
    };
    let config: FileConfig = toml::from_str("format = \"sarif\"").unwrap();
    let command_matches = matches.subcommand_matches("scan").unwrap();

    let error = apply(&mut scan.options, config, None, command_matches, false).unwrap_err();

    assert!(error.to_string().contains("--verbose is only valid"));
}
