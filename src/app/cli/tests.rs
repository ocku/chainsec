use chainsec::RemoteVersionSelection;
use clap::Parser;

use super::{Cli, Command, RemoteSubcommand};

#[test]
fn parses_remote_scan() {
    let cli = Cli::try_parse_from(["chainsec", "remote", "scan", "npm:express"]).unwrap();
    let Command::Remote(remote) = cli.command else {
        panic!("expected remote command")
    };
    let RemoteSubcommand::Scan(scan) = remote.command else {
        panic!("expected remote scan command")
    };

    assert_eq!(scan.package, "npm:express");
    assert_eq!(scan.diff, None);
}

#[test]
fn parses_remote_scan_diff_convenience_option() {
    let cli =
        Cli::try_parse_from(["chainsec", "remote", "scan", "npm:express", "--diff", "3"]).unwrap();
    let Command::Remote(remote) = cli.command else {
        panic!("expected remote command")
    };
    let RemoteSubcommand::Scan(scan) = remote.command else {
        panic!("expected remote scan command")
    };

    assert_eq!(scan.diff, Some(3));
    for count in ["0", "1"] {
        assert!(
            Cli::try_parse_from(["chainsec", "remote", "scan", "npm:express", "--diff", count,])
                .is_err()
        );
    }
}

#[test]
fn parses_remote_diff_last_selection() {
    let cli =
        Cli::try_parse_from(["chainsec", "remote", "diff", "npm:express", "--last", "3"]).unwrap();
    let Command::Remote(remote) = cli.command else {
        panic!("expected remote command")
    };
    let RemoteSubcommand::Diff(diff) = remote.command else {
        panic!("expected remote diff command")
    };

    assert_eq!(diff.package, "npm:express");
    assert_eq!(diff.last, Some(3));
    assert_eq!(diff.selection(), RemoteVersionSelection::Last(3));
    assert!(diff.compare.is_none());
    assert!(diff.range.is_none());
    for count in ["0", "1"] {
        assert!(
            Cli::try_parse_from(["chainsec", "remote", "diff", "npm:express", "--last", count,])
                .is_err()
        );
    }
}

#[test]
fn parses_remote_diff_compare_selection() {
    let cli = Cli::try_parse_from([
        "chainsec",
        "remote",
        "diff",
        "pypi:requests",
        "--compare",
        "2.31.0",
        "2.32.0",
    ])
    .unwrap();
    let Command::Remote(remote) = cli.command else {
        panic!("expected remote command")
    };
    let RemoteSubcommand::Diff(diff) = remote.command else {
        panic!("expected remote diff command")
    };

    assert_eq!(
        diff.compare.as_deref(),
        Some(["2.31.0".to_owned(), "2.32.0".to_owned()].as_slice())
    );
    assert_eq!(
        diff.selection(),
        RemoteVersionSelection::Compare {
            from: "2.31.0".to_owned(),
            to: "2.32.0".to_owned(),
        }
    );
}

#[test]
fn parses_remote_diff_range_selection() {
    let cli = Cli::try_parse_from([
        "chainsec",
        "remote",
        "diff",
        "npm:express",
        "--range",
        "4.18.0",
        "5.0.0",
    ])
    .unwrap();
    let Command::Remote(remote) = cli.command else {
        panic!("expected remote command")
    };
    let RemoteSubcommand::Diff(diff) = remote.command else {
        panic!("expected remote diff command")
    };

    assert_eq!(
        diff.range.as_deref(),
        Some(["4.18.0".to_owned(), "5.0.0".to_owned()].as_slice())
    );
    assert_eq!(
        diff.selection(),
        RemoteVersionSelection::Range {
            from: "4.18.0".to_owned(),
            to: "5.0.0".to_owned(),
        }
    );
}

#[test]
fn remote_diff_requires_exactly_one_selection() {
    assert!(Cli::try_parse_from(["chainsec", "remote", "diff", "npm:express"]).is_err());
    assert!(
        Cli::try_parse_from([
            "chainsec",
            "remote",
            "diff",
            "npm:express",
            "--last",
            "2",
            "--compare",
            "4.18.0",
            "5.0.0",
        ])
        .is_err()
    );
}

#[test]
fn remote_diff_compare_and_range_require_exactly_two_values() {
    for selector in ["--compare", "--range"] {
        assert!(
            Cli::try_parse_from([
                "chainsec",
                "remote",
                "diff",
                "npm:express",
                selector,
                "4.18.0",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "chainsec",
                "remote",
                "diff",
                "npm:express",
                selector,
                "4.18.0",
                "4.19.0",
                "5.0.0",
            ])
            .is_err()
        );
    }
}

#[test]
fn threads_default_to_sixteen_and_must_be_between_one_and_sixty_four() {
    let cli = Cli::try_parse_from(["chainsec", "scan"]).unwrap();
    let Command::Scan(scan) = cli.command else {
        panic!("expected scan command")
    };
    assert_eq!(scan.options.threads, 16);

    assert!(Cli::try_parse_from(["chainsec", "scan", "--threads", "0"]).is_err());
    assert!(Cli::try_parse_from(["chainsec", "scan", "--threads", "65"]).is_err());
    assert!(Cli::try_parse_from(["chainsec", "scan", "--threads", "64"]).is_ok());
}

#[test]
fn ignore_path_accepts_repeated_globs() {
    let cli = Cli::try_parse_from([
        "chainsec",
        "scan",
        "--ignore-path",
        "tests/**",
        "--ignore-path",
        "generated/**",
    ])
    .unwrap();
    let Command::Scan(scan) = cli.command else {
        panic!("expected scan command")
    };

    assert_eq!(scan.options.ignored_paths, ["tests/**", "generated/**"]);
}
